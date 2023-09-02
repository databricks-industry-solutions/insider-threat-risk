# Databricks notebook source
# MAGIC %md
# MAGIC
# MAGIC # Per User Anomaly Detection Using Python Outlier Detection (PYOD) Library 
# MAGIC
# MAGIC This notebook demonstrates how to extend the per user (per modality) anomaly model approach in `03_anomaly_detection_gaussian` to use all the outlier detection models available in the Python Outler Detection (PYOD) library.
# MAGIC
# MAGIC We will only show the logic for the `web` data source (that tracks user web upload activities) and leave the application of the same logic to the other data sources.
# MAGIC
# MAGIC ## Technical Overview
# MAGIC
# MAGIC The general idea is to encapsulate the model training operation and the prediction operation into two user defined functions (UDFs) that can be called and parallelized by spark. 
# MAGIC * The model training UDF will take a json representation of the training data as input and return a serialized string encoding of the PYOD model.
# MAGIC * The prediction UDF will take the serialized string of the model and the json representation of the observation vector and return the output of the PYOD prediction.
# MAGIC
# MAGIC ## Production Use
# MAGIC
# MAGIC In production, you would deploy two workflow jobs:
# MAGIC 1. One job to update the per user per modality models periodically. If you use tumbling yearly periods then update the models once a year. If you use a one-year window sliding monthly, you can update monthly. 
# MAGIC 2. One job to do the inferencing/detection over a window (e.g. three months) of data sliding periodically (e.g. weekly).
# MAGIC
# MAGIC The current notebook uses a time granularity of one week, so each feature vector covers the behavior for one week. The ideal frequency for inferencing is then one week, so that you do not have to pad or extrapolate the feature vector.
# MAGIC
# MAGIC Updating the model more frequently does not necessarily create more accurate detections. In fact, frequent updates run the risk of unintentionally incorporating malicious behavior into the baseline of the anomaly models.

# COMMAND ----------

# MAGIC %pip install numpy==1.22
# MAGIC %pip install pyod

# COMMAND ----------

dbutils.library.restartPython()

# COMMAND ----------

# MAGIC %run ./config/notebook_config

# COMMAND ----------

# DBTITLE 1,Setup default catalog and schema
sql_list = [ 
  f"use catalog hive_metastore",
  f"use schema {getParam('db')}",
  "select * from web"
]

for sql_str in sql_list:
  df = spark.sql(sql_str)
  display(df)


# COMMAND ----------

# DBTITLE 1,Implementation of the UDFs 
import pickle
import base64
import json
import numpy as np
from pyod.models.ecod import ECOD
from pyspark.sql.types import *

# the lack of error checking logic is intentional to optimize the execution time
# unit and integration test at dev time should be used to minimize error conditions

def serialize(model):
  model_pickle = pickle.dumps(model)
  b64 = base64.b64encode(model_pickle)
  model_str = b64.decode("ascii")
  return model_str

def deserialize(model_str):
  b64 = model_str.encode('ascii')
  model_pickle = base64.decodebytes(b64)
  model = pickle.loads(model_pickle)
  return model

def pyod_fit(train_json_str):
  train_json = json.loads(train_json_str)
  train = np.array(train_json)
  model = ECOD()
  model.fit(train)
  model_str = serialize(model)
  #model_str = "testing"
  return model_str

def pyod_predict(model_str, x_json_str):
  model = ECOD() # this is to force spark to include the ECOD class when packaging the UDF.
  model = deserialize(model_str)
  x_json = json.loads(x_json_str)
  x = np.array([x_json])
  y = model.predict(x)
  return str(y[0])

def sanity_tests():
  trg = [ [1, 2], [2,2], [3,2], [1.5, 2] ]
  print("---------------------------------")
  print("Test the serialization/deserialization")
  print("---------------------------------")
  model = ECOD()
  trg_data = np.array(trg)
  model.fit(trg_data)
  model_str = serialize(model)
  model_recon = deserialize(model_str)
  print(f"deserialized model matches = {model.get_params() ==model_recon.get_params()}")

  print("---------------------------------")
  print("Test the training UDF in py")
  print("---------------------------------")
  trg_str = json.dumps(trg)
  print(f"trg_str = {trg_str}")
  m_str = pyod_fit(trg_str)
  print(f"m_str=\n{m_str}")
  print("---------------------------------")
  print("Test the inferencing UDF in py")
  print("---------------------------------")
  tst = [4,3]
  tst_str = json.dumps(tst)
  y = pyod_predict(m_str, tst_str)
  print(f"is_outlier = {str(y)}")

spark.udf.register("pyod_fit", pyod_fit, StringType())
spark.udf.register("pyod_predict", pyod_predict, StringType())

sanity_tests()

# COMMAND ----------

# DBTITLE 1,Sanity test of UDFs in SQL 
# MAGIC %sql
# MAGIC
# MAGIC select pyod_fit('[[1, 2], [2,2], [3,2], [1.5, 2]]') as model_str;
# MAGIC select pyod_predict('gASV3QMAAAAAAACMEHB5b2QubW9kZWxzLmVjb2SUjARFQ09ElJOUKYGUfZQojA1jb250YW1pbmF0aW9ulEc/uZmZmZmZmowGbl9qb2JzlEsBjAhfY2xhc3Nlc5RLAowDVV9slIwVbnVtcHkuY29yZS5tdWx0aWFycmF5lIwMX3JlY29uc3RydWN0lJOUjAVudW1weZSMB25kYXJyYXmUk5RLAIWUQwFilIeUUpQoSwFLBEsChpRoDIwFZHR5cGWUk5SMAmY4lImIh5RSlChLA4wBPJROTk5K/////0r/////SwB0lGKJQ0DvOfr+Qi72PwAAAAAAAACAkts0EWJp0j8AAAAAAAAAgAAAAAAAAACAAAAAAAAAAIDvOfr+Qi7mPwAAAAAAAACAlHSUYowDVV9ylGgLaA5LAIWUaBCHlFKUKEsBSwRLAoaUaBiJQ0AAAAAAAAAAgAAAAAAAAACA7zn6/kIu5j8AAAAAAAAAgO85+v5CLvY/AAAAAAAAAICS2zQRYmnSPwAAAAAAAACAlHSUYowGVV9za2V3lGgLaA5LAIWUaBCHlFKUKEsBSwRLAoaUaBiJQ0AAAAAAAAAAgAAAAAAAAACA7zn6/kIu5j8AAAAAAAAAgO85+v5CLvY/AAAAAAAAAICS2zQRYmnSPwAAAAAAAACAlHSUYowBT5RoC2gOSwCFlGgQh5RSlChLAUsESwKGlGgYiUNA7zn6/kIu9j8AAAAAAAAAgO85+v5CLuY/AAAAAAAAAIDvOfr+Qi72PwAAAAAAAACA7zn6/kIu5j8AAAAAAAAAgJR0lGKMEGRlY2lzaW9uX3Njb3Jlc1+UaAtoDksAhZRoEIeUUpQoSwFLBIWUaBiJQyDvOfr+Qi72P+85+v5CLuY/7zn6/kIu9j/vOfr+Qi7mP5R0lGKMB1hfdHJhaW6UaAtoDksAhZRoEIeUUpQoSwFLBEsChpRoGIlDQAAAAAAAAPA/AAAAAAAAAEAAAAAAAAAAQAAAAAAAAABAAAAAAAAACEAAAAAAAAAAQAAAAAAAAPg/AAAAAAAAAECUdJRijAp0aHJlc2hvbGRflGgJjAZzY2FsYXKUk5RoGEMI7zn6/kIu9j+UhpRSlIwHbGFiZWxzX5RoC2gOSwCFlGgQh5RSlChLAUsEhZRoFYwCaTiUiYiHlFKUKEsDaBlOTk5K/////0r/////SwB0lGKJQyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJR0lGKMA19tdZRoQmgYQwhzqzs/sqLwP5SGlFKUjAZfc2lnbWGUaEJoGEMI7zn6/kIu1j+UhpRSlHViLg==', '[4,3]') as is_outlier;

# COMMAND ----------

# MAGIC %md
# MAGIC
# MAGIC ## Updating the anomaly model
# MAGIC
# MAGIC * We use a tumbling yearly window of data for training the web upload pattern model for each user. Sliding windows are certainly possible, but may be more susceptible to the anomalous behavior becoming part of the baseline.
# MAGIC * For a year's worth of data, we consider only the daily upload byte sizes and split the daily data into weekly vectors. Each weekly vector has seven integers each denoting the total upload sizes for each day of that week.
# MAGIC * To ensure that each weekly feature vector we extract from the data has cardinality seven, we create the weekly sequence for each user as a kind of `feature schema` to left join with the data.
# MAGIC * The start and end date of the training data has to be aligned to weekly boundaries, so that every feature vector has cardinality seven for each feature type. Since we only use the daily upload size, each weekly vector has cardinality seven.  
# MAGIC * We use view definitions to make the SQL more readable.
# MAGIC

# COMMAND ----------

# DBTITLE 1,Check the date range of the data set
# MAGIC %sql
# MAGIC select min(ts), max(ts)
# MAGIC from web

# COMMAND ----------

# MAGIC %md
# MAGIC
# MAGIC This feature vector schema `view` should be updated weekly with the end date if you plan to use the same weekly view for inference as well.

# COMMAND ----------

# DBTITLE 1,Setup the feature vector "schema" to ensure consistency
# MAGIC %sql
# MAGIC
# MAGIC -- we need to set the start and end timestamps to be aligned on weekly boundaries
# MAGIC drop view if exists vector_schema;
# MAGIC create view if not exists vector_schema
# MAGIC as
# MAGIC select u.userid, t.ts_day
# MAGIC from 
# MAGIC (
# MAGIC   select col as ts_day
# MAGIC   from explode(sequence(TIMESTAMP'2019-01-07', TIMESTAMP'2021-01-03', INTERVAL 1 DAY))
# MAGIC ) as t,
# MAGIC (
# MAGIC   select distinct userid
# MAGIC   from web
# MAGIC ) as u;
# MAGIC
# MAGIC -- test query on the view
# MAGIC select *
# MAGIC from (
# MAGIC   select userid, date_trunc('WEEK', ts_day) as ts_week, 
# MAGIC     count(*) as cnt
# MAGIC   from vector_schema
# MAGIC   group by userid, ts_week
# MAGIC )
# MAGIC where cnt <> 7 ;

# COMMAND ----------

# DBTITLE 1,Setup the view with the weekly feature vectors for each user
# MAGIC %sql
# MAGIC
# MAGIC drop view if exists web_weekly_vecs;
# MAGIC create view if not exists web_weekly_vecs
# MAGIC as
# MAGIC select t.userid, 
# MAGIC   date_trunc('WEEK', t.ts_day) as ts_week, 
# MAGIC   array_agg(case when w.daily_web_size is null then 0 else w.daily_web_size end) as vec
# MAGIC   --t.ts_day, w.daily_web_size
# MAGIC from
# MAGIC   vector_schema as t 
# MAGIC   left outer join 
# MAGIC   (
# MAGIC     select userid, 
# MAGIC       date_trunc('DAY', ts) as ts_day, 
# MAGIC       sum(size_in_bytes)::float as daily_web_size
# MAGIC     from web
# MAGIC     where activity in ('upload')
# MAGIC     group by userid, ts_day
# MAGIC   ) as w on t.userid=w.userid and t.ts_day = w.ts_day
# MAGIC group by t.userid, ts_week;
# MAGIC  
# MAGIC select *
# MAGIC from web_weekly_vecs;

# COMMAND ----------

# DBTITLE 1,Setup the view to construct the training data for each user
# MAGIC %sql
# MAGIC
# MAGIC drop view if exists web_training;
# MAGIC create view if not exists web_training
# MAGIC as
# MAGIC select
# MAGIC   userid,
# MAGIC   date_trunc('YEAR', ts_week) as ts_year,
# MAGIC   to_json(array_agg(vec)) as x_train
# MAGIC from web_weekly_vecs
# MAGIC group by userid, ts_year;
# MAGIC
# MAGIC select * 
# MAGIC from web_training;

# COMMAND ----------

# MAGIC %md
# MAGIC
# MAGIC * This notebook took the simple approach of overwriting the `models` table with the latest models. You can certainly apply versioning and keep appending models to the `models` table instead.

# COMMAND ----------

# DBTITLE 1,Update the models table
# MAGIC %sql
# MAGIC
# MAGIC drop table if exists models;
# MAGIC create table if not exists models (userid string, model_str string);
# MAGIC
# MAGIC insert overwrite models
# MAGIC (
# MAGIC select userid, 
# MAGIC   pyod_fit(x_train) as model_str
# MAGIC from web_training
# MAGIC where ts_year = '2019-01-01T00:00:00.000+0000'::timestamp
# MAGIC );

# COMMAND ----------

# DBTITLE 1,Sanity check the models table
# MAGIC %sql
# MAGIC
# MAGIC select * from models

# COMMAND ----------

# MAGIC %md
# MAGIC
# MAGIC ## Inferencing 

# COMMAND ----------

# MAGIC %sql
# MAGIC
# MAGIC select v.userid, v.ts_week, to_json(v.vec), pyod_predict(m.model_str, to_json(v.vec)) as is_outlier
# MAGIC from web_weekly_vecs as v 
# MAGIC   left outer join models as m on v.userid=m.userid  
# MAGIC where ts_week > '2021-01-01'::date - '12 WEEKS'::interval

# COMMAND ----------

# MAGIC %md
# MAGIC
# MAGIC At this point, we can plug these outlier counts into the weighted risk scoring framework in `03_anomaly_detection_gaussian.py` 

# COMMAND ----------


