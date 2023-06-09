# Databricks notebook source
# MAGIC %md
# MAGIC
# MAGIC # Statistics-based Anomaly Detection for Insider Data Exfiltration
# MAGIC
# MAGIC There are two extreme cases in data exfiltration incidents:
# MAGIC * Case 1: big data dump in a single event 
# MAGIC * Case 2: small data dumps over multiple events over longer periods of time
# MAGIC
# MAGIC Case 1 is obviously the easy case to detect and is well handled by the detection rules in current systems/technology.
# MAGIC Case 2 is much hard to detect and is the focus of this notebook.
# MAGIC
# MAGIC ## Assumptions
# MAGIC * Data can be exfiltrated in multiple modalities: electronically (emails, http, etc.) or copied to removable media or printed to hardcopies
# MAGIC * Every individual is different in their routine and usage patterns - we want individual profiles/models
# MAGIC * The insider threat actor can and will spread their exfiltration tasks over multiple modalities to hide their tracks
# MAGIC
# MAGIC ## Overview of the anomaly detection method
# MAGIC
# MAGIC * Build statistical baselines based on the previous year for each individual
# MAGIC * For each individual, we model the baseline profile for each exfiltration modality (email, http, file etc.) with a Gaussian model (mean and standard deviation).
# MAGIC * For each exfiltration modality, we model the behavior as a weekly count/profile of some exfiltration event (which in itself can be a normal behavior).
# MAGIC * For each individual, an anomaly is when the weekly profile exceeds three standard deviations from the individual's baseline - This in itself is likely not a sufficient indicator for alerting, so we aggregate these over longer time periods in order to create an anomaly score for that individual.
# MAGIC * The anomaly detection will use the previous years (sliding window) baselines.
# MAGIC * We do fusion of the anomalies in multiple modalities for an individual to mitigate threat actors masking their tracks with spreading their exfiltration task across different modalities.
# MAGIC
# MAGIC ## Use case scenarios
# MAGIC
# MAGIC * Anomaly alerting on a weekly cadence
# MAGIC * Periodic hunts of users with anomalous/suspicious exfiltration behavior over a long time range
# MAGIC

# COMMAND ----------

# MAGIC %md
# MAGIC
# MAGIC # Creating the baselines for each individual for each exfiltration modality
# MAGIC
# MAGIC You have a choice of using either views or materialized views/tables for the baselines. Materialized views will be more performant at query time at the cost of table creation and maintenance. We use views below to demonstrate the flexibility and scalability of the platform.
# MAGIC

# COMMAND ----------

# MAGIC %sql
# MAGIC
# MAGIC use schema lipyeow_insider;

# COMMAND ----------

# DBTITLE 1,Baselines for removable media file write events
# MAGIC %sql
# MAGIC
# MAGIC drop view if exists v_file_baselines;
# MAGIC create view if not exists v_file_baselines 
# MAGIC as
# MAGIC select userid, ts_year, avg(file_cnt) as avg_cnt, min(file_cnt) as min_cnt, max(file_cnt) as max_cnt, stddev(file_cnt) as std_dev
# MAGIC from
# MAGIC (
# MAGIC   select userid, date_trunc('YEAR', ts) as ts_year, date_trunc('WEEK', ts) as ts_week, count(*) as file_cnt
# MAGIC   from file
# MAGIC   where to_media = 'True' and activity in ('write', 'copy')
# MAGIC   group by userid, ts_year, ts_week
# MAGIC )
# MAGIC group by userid, ts_year

# COMMAND ----------

# MAGIC %sql
# MAGIC
# MAGIC select *
# MAGIC from v_file_baselines
# MAGIC order by userid, ts_year;

# COMMAND ----------

# DBTITLE 1,Baselines for external-outbound email attachment sizes
# MAGIC %sql
# MAGIC
# MAGIC drop view if exists v_email_baselines;
# MAGIC create view if not exists v_email_baselines 
# MAGIC as
# MAGIC select userid, ts_year, avg(total_email_size) as avg_size, min(total_email_size) as min_size, max(total_email_size) as max_size, stddev(total_email_size) as std_dev
# MAGIC from
# MAGIC (
# MAGIC   select userid, date_trunc('YEAR', ts) as ts_year, date_trunc('WEEK', ts) as ts_week, sum(email_size + attachment_size) as total_email_size
# MAGIC   from 
# MAGIC   (
# MAGIC     select *, explode(split(`to`, ';')) as recv
# MAGIC     from email
# MAGIC   )
# MAGIC   where not recv like '%xyz.com%'
# MAGIC   group by userid, ts_year, ts_week
# MAGIC )
# MAGIC group by userid, ts_year

# COMMAND ----------

# MAGIC %sql
# MAGIC
# MAGIC select *
# MAGIC from v_email_baselines
# MAGIC order by userid, ts_year;

# COMMAND ----------

# DBTITLE 1,Baselines for HTTP upload events
# MAGIC %sql
# MAGIC
# MAGIC drop view if exists v_http_baselines;
# MAGIC create view if not exists v_http_baselines 
# MAGIC as
# MAGIC select userid, ts_year, avg(web_cnt) as avg_cnt, min(web_cnt) as min_cnt, max(web_cnt) as max_cnt, stddev(web_cnt) as std_dev
# MAGIC from
# MAGIC (
# MAGIC   select userid, date_trunc('YEAR', ts) as ts_year, date_trunc('WEEK', ts) as ts_week, count(*) as web_cnt
# MAGIC   from web
# MAGIC   where activity in ('upload')
# MAGIC   group by userid, ts_year, ts_week
# MAGIC )
# MAGIC group by userid, ts_year

# COMMAND ----------

# MAGIC %sql
# MAGIC
# MAGIC select *
# MAGIC from v_http_baselines
# MAGIC order by userid, ts_year;

# COMMAND ----------

# MAGIC %md
# MAGIC
# MAGIC # Checking the data for anomalies

# COMMAND ----------

# DBTITLE 1,Removable Media Write Anomalies
# MAGIC %sql
# MAGIC
# MAGIC drop view if exists v_file_anomalies;
# MAGIC
# MAGIC create view if not exists v_file_anomalies
# MAGIC as
# MAGIC select userid, 'file' as anomaly_type, count(*) as anomaly_cnt
# MAGIC from
# MAGIC (
# MAGIC   select f.userid, f.ts_year, b.ts_year, f.ts_week, f.file_cnt, b.avg_cnt, b.std_dev, b.avg_cnt + 3*b.std_dev as threshold
# MAGIC   from 
# MAGIC   (
# MAGIC     select userid, date_trunc('YEAR', ts) as ts_year, date_trunc('WEEK', ts) as ts_week, count(*) as file_cnt
# MAGIC     from file
# MAGIC     where to_media = 'True' and activity in ('write', 'copy')
# MAGIC     group by userid, ts_year, ts_week
# MAGIC   ) as f join v_file_baselines as b on f.userid = b.userid and b.ts_year = f.ts_year - '1 year'::interval
# MAGIC   where f.file_cnt > b.avg_cnt + 3*b.std_dev
# MAGIC       and f.ts_year >= '2020-01-01T00:00:00.000+0000'
# MAGIC )
# MAGIC group by userid;

# COMMAND ----------

# MAGIC %sql
# MAGIC
# MAGIC select *
# MAGIC from v_file_anomalies
# MAGIC order by anomaly_cnt desc

# COMMAND ----------

# DBTITLE 1,External-Outbound Email Attachment Size Anomalies 
# MAGIC %sql
# MAGIC
# MAGIC drop view if exists v_email_anomalies;
# MAGIC
# MAGIC create view if not exists v_email_anomalies
# MAGIC as
# MAGIC select userid, 'email' as anomaly_type, count(*) as anomaly_cnt
# MAGIC from
# MAGIC (
# MAGIC   select f.userid, f.ts_year, b.ts_year, f.ts_week, f.total_email_size, b.avg_size, b.std_dev, b.avg_size + 3*b.std_dev as threshold
# MAGIC   from 
# MAGIC   (
# MAGIC     select userid, date_trunc('YEAR', ts) as ts_year, date_trunc('WEEK', ts) as ts_week, sum(email_size+attachment_size) as total_email_size
# MAGIC     from 
# MAGIC     (
# MAGIC       select *, explode(split(`to`, ';')) as recv
# MAGIC       from email
# MAGIC     )
# MAGIC     where not recv like '%xyz.com%'
# MAGIC     group by userid, ts_year, ts_week
# MAGIC   ) as f join v_email_baselines as b on f.userid = b.userid and b.ts_year = f.ts_year - '1 year'::interval
# MAGIC   where f.total_email_size > b.avg_size + 3*b.std_dev
# MAGIC       and f.ts_year >= '2011-01-01T00:00:00.000+0000'
# MAGIC )
# MAGIC group by userid
# MAGIC

# COMMAND ----------

# MAGIC %sql
# MAGIC
# MAGIC select f.userid, f.ts_year, b.ts_year, f.ts_week, f.total_email_size, b.avg_size, b.std_dev, b.avg_size + 3*b.std_dev as threshold
# MAGIC from 
# MAGIC   (
# MAGIC     select userid, date_trunc('YEAR', ts) as ts_year, date_trunc('WEEK', ts) as ts_week, sum(email_size+attachment_size) as total_email_size
# MAGIC     from 
# MAGIC     (
# MAGIC       select *, explode(split(`to`, ';')) as recv
# MAGIC       from email
# MAGIC     )
# MAGIC     where not recv like '%xyz.com%'
# MAGIC     group by userid, ts_year, ts_week
# MAGIC   ) as f join v_email_baselines as b on f.userid = b.userid and b.ts_year = f.ts_year - '1 year'::interval
# MAGIC --where f.total_email_size > b.avg_size
# MAGIC

# COMMAND ----------

# MAGIC %sql
# MAGIC
# MAGIC select *
# MAGIC from v_email_anomalies
# MAGIC order by anomaly_cnt desc

# COMMAND ----------

# DBTITLE 1,HTTP Upload Anomalies
# MAGIC %sql
# MAGIC
# MAGIC drop view if exists v_http_anomalies;
# MAGIC
# MAGIC create view if not exists v_http_anomalies
# MAGIC as
# MAGIC select userid, 'http' as anomaly_type, count(*) as anomaly_cnt
# MAGIC from
# MAGIC (
# MAGIC   select f.userid, f.ts_year, b.ts_year, f.ts_week, f.http_cnt, b.avg_cnt, b.std_dev, b.avg_cnt + 3*b.std_dev as threshold
# MAGIC   from 
# MAGIC   (
# MAGIC     select userid, date_trunc('YEAR', ts) as ts_year, date_trunc('WEEK', ts) as ts_week, count(*) as http_cnt
# MAGIC     from web
# MAGIC     where activity in ('upload')
# MAGIC     group by userid, ts_year, ts_week
# MAGIC   ) as f join v_http_baselines as b on f.userid = b.userid and b.ts_year = f.ts_year - '1 year'::interval
# MAGIC   where f.http_cnt > b.avg_cnt + 3*b.std_dev
# MAGIC       and f.ts_year >= '2011-01-01T00:00:00.000+0000'
# MAGIC )
# MAGIC group by userid;

# COMMAND ----------

# MAGIC %sql
# MAGIC
# MAGIC select *
# MAGIC from v_http_anomalies
# MAGIC order by anomaly_cnt desc

# COMMAND ----------

# MAGIC %md
# MAGIC
# MAGIC # Fusion Insider Scoring
# MAGIC
# MAGIC * This will help catch threat actors that try to spread their exfiltration load across multiple modalities
# MAGIC * The weights will need to be tuned for the specific organizational environment

# COMMAND ----------

# MAGIC %sql
# MAGIC
# MAGIC select userid, anomaly_score, map_from_arrays(a_types, a_cnts) as details
# MAGIC from (
# MAGIC   select userid, sum(wt_anomaly_cnt) as anomaly_score, array_agg(anomaly_type) as a_types, array_agg(anomaly_cnt) as a_cnts
# MAGIC   from
# MAGIC   (
# MAGIC     select userid, anomaly_type, anomaly_cnt, 1.0 * anomaly_cnt as wt_anomaly_cnt
# MAGIC     from v_file_anomalies
# MAGIC     union all
# MAGIC     select userid, anomaly_type, anomaly_cnt, 0.3 * anomaly_cnt as wt_anomaly_cnt
# MAGIC     from v_email_anomalies
# MAGIC     union all
# MAGIC     select userid, anomaly_type, anomaly_cnt, 0.5 * anomaly_cnt as wt_anomaly_cnt
# MAGIC     from v_http_anomalies
# MAGIC   )
# MAGIC   group by userid
# MAGIC   order by anomaly_score desc
# MAGIC   limit 20
# MAGIC )

# COMMAND ----------


