# Databricks notebook source
# MAGIC %md
# MAGIC
# MAGIC # Generate Data for the Insider Threat Use Case
# MAGIC
# MAGIC 1. generate a collection of users
# MAGIC 2. for each user, simulate the user's activities (email, file, http, print) within a time unit based on the pre-configured probabilities in the `cfg` dictionary. Write the logs for the activities in batches to csv files in DBFS.
# MAGIC 3. Load the csv files into delta tables
# MAGIC
# MAGIC The simulation used to generate the data is completely serial and runs in the driver node. Simulating 1000 users over two years took can take up to 100 minutes. The simulation can be easily parallelized, but is not the focus of this solution accelerator.
# MAGIC
# MAGIC All parameters associated with the data generation is controlled by the `cfg` dictionary. Modify the parameters in the `cfg` creation command below. 

# COMMAND ----------

# MAGIC %pip install faker
# MAGIC

# COMMAND ----------

# MAGIC %run ./config/notebook_config

# COMMAND ----------

# DBTITLE 1,Define simulation and data generation routines
from faker import Faker
import random
import json
import time
from datetime import timezone, datetime, timedelta
from pyspark.sql.types import *
import pandas as pd
from typing import Iterator
from pyspark.sql.functions import col, pandas_udf, struct
import uuid
import collections
import csv
import os

# schema: name, email, userid
def generate_user_tuple(company="xyz.com"):
  user = []
  name = fake.unique.name()
  user.append(name)
  user.append(name.lower().replace(" ", ".") + "@" + company)
  user.append(name.lower().replace(" ", "."))
  return user

def simulate_user_activity(cfg):
  # open csv output files
  fh = {}
  wh = {}
  for data_type in cfg["schemas"].keys():
    csv_fname = os.path.join(cfg["tmpdir"], data_type + ".csv")
    f = open(csv_fname , "w")
    fh[data_type] = f
    wh[data_type] = csv.writer(f)

  cur_ts = cfg["start_ts"]
  while( cur_ts < cfg["end_ts"] ):
    next_ts = cur_ts + timedelta(days=cfg["batch_size_days"])
    print(f"simulating for batch time period {cur_ts.isoformat()} - {next_ts.isoformat()}")
    batch_data = simulate_user_activity_one_batch(cfg, cur_ts, next_ts, timedelta(minutes=cfg["sim_unit_min"]))
    for data_type in cfg["schemas"].keys():
      print(f"{data_type} : {len(batch_data[data_type])}")
      for r in batch_data[data_type]:
        wh[data_type].writerow(r)
    cur_ts = next_ts
  # close all the files  
  for data_type, f in fh.items():
    f.close()

def simulate_user_activity_one_batch(cfg, batch_start_ts, batch_end_ts, sim_timedelta):
  # init data to hold data for one batch in memory on driver node
  data = {}
  for data_type in cfg["schemas"].keys():
    data[data_type] = []
  # for each day in time period
  cur_ts = batch_start_ts
  while( cur_ts < batch_end_ts ):
    next_ts = cur_ts + sim_timedelta
    #print(f"simulating for unit time period {cur_ts.isoformat()} - {next_ts.isoformat()}")
    for u in cfg["users"]:
      # simulate file activity
      if random.random() < cfg["prob_file"]:
        f = generate_file_tuple(cfg, cur_ts, next_ts, u[2])
        #print(f"{u[0]}: file activity\n  {str(f)}")
        data["file"].append(f)
      # simulate email activity
      if random.random() < cfg["prob_email"]:
        #print(f"{u[0]}: email activity")
        rows = simulate_email_traffic(cfg, cur_ts, next_ts, u)
        data["email"].extend(rows)
        #for r in rows:
        #  print(f"  {str(r)}")
      # simulate web activity
      if random.random() < cfg["prob_web"]:
        #print(f"{u[0]}: web activity")
        w = generate_web_tuple(cfg, cur_ts, next_ts, u[2])
        data["web"].append(w)
      # simulate print activity
      if random.random() < cfg["prob_print"]:
        #print(f"{u[0]}: print activity")
        w = generate_print_tuple(cfg, cur_ts, next_ts, u[2])
        data["print"].append(w)
      #print("====================")
    cur_ts = next_ts
  return data

# schema: ts, userid, pc, filename, activity, to_media, from_media, size_in_bytes
def generate_file_tuple(cfg, start_ts, end_ts, userid):
  row = []
  ts = fake.date_time_between(start_ts, end_ts, timezone.utc)
  row.append(ts.isoformat())
  row.append(userid)
  row.append("pc-"+str(random.randrange(cfg["pc_cnt"])))
  row.append(fake.file_path(depth=3))
  row.append(random.choice(cfg["file_activity_list"]))
  row.append(random.choice(["True", "False"]))
  row.append(random.choice(["True", "False"]))
  row.append(abs(int(random.gauss(1000, 10000))))
  return row

# schema: ts, userid, pc, to, cc, bcc, from, activity, email_size, attachment_size
# to/cc/bcc fields are ;-separated lists
def create_email_tuple(cfg, ts, userid, pc, to, cc, bcc, sender, activity, email_size, attachment_size):
  row = []
  row.append(ts.isoformat())
  row.append(userid)
  row.append(pc)
  row.append(";".join(to))
  row.append(";".join(cc))
  row.append(";".join(bcc))
  row.append(sender)
  row.append(activity)
  row.append(email_size)
  row.append(attachment_size)
  return row

# for this email, generate the send tuple, and the view tuples for all internal recipients
def generate_email_tuples(cfg, ts, sender, to, cc, bcc):
  tlist = []
  email_size = abs(int(random.gauss(1000, 10000)))
  attachment_size = 0
  if random.random()<0.1:
    attachment_size = abs(int(random.gauss(1000, 100000)))
  if sender[-7:]=="xyz.com":
    pc = "pc-"+str(random.randrange(cfg["pc_cnt"]))
    tlist.append(create_email_tuple(cfg, ts, sender[:-8], pc, to, cc, bcc, sender, "send", email_size, attachment_size))
  recvlist = []
  recvlist.extend(to)
  recvlist.extend(cc)
  recvlist.extend(bcc)
  for r in recvlist:
    if r[-7:]=="xyz.com":
      pc = "pc-"+str(random.randrange(cfg["pc_cnt"]))
      tlist.append(create_email_tuple(cfg, ts, r[:-8], pc, to, cc, bcc, sender, "view", email_size, attachment_size))
  return tlist

# simulate email traffic for a single given user
# internal user sends an email to internal/external
# assume that for each internal user there is an external user who 
# sends an email to internal and/or external users
def simulate_email_traffic(cfg, start_ts, end_ts, sender_user):
  tlist = []
  for sender in ( sender_user[1], "some@external.sender" ):
    ts = fake.date_time_between(start_ts, end_ts, timezone.utc)
    to = random.sample(cfg["all_emails"], random.randint(1,7))
    cc = random.sample(cfg["all_emails"], random.randint(1,7))
    if random.random()<0.1:
      bcc = random.sample(cfg["all_emails"], random.randint(1,3))
    else:
      bcc = []
    tlist.extend(generate_email_tuples(cfg, ts, sender, to, cc, bcc))
  return tlist


# web activity (download, upload, visit)
# schema: ts, userid, pc, url, activity, size_in_bytes
def generate_web_tuple(cfg, start_ts, end_ts, userid):
  row = []
  ts = fake.date_time_between(start_ts, end_ts, timezone.utc)
  row.append(ts.isoformat())
  row.append(userid)
  row.append("pc-"+str(random.randrange(cfg["pc_cnt"])))
  row.append(fake.uri())
  row.append(random.choice(cfg["web_activity_list"]))
  row.append(abs(int(random.gauss(1000, 100000))))
  return row

# print activity
# schema: ts, userid, pc, printer, document_name, activity, print_size
def generate_print_tuple(cfg, start_ts, end_ts, userid):
  row = []
  ts = fake.date_time_between(start_ts, end_ts, timezone.utc)
  row.append(ts.isoformat())
  row.append(userid)
  row.append("pc-"+str(random.randrange(cfg["pc_cnt"])))
  row.append("printer-"+str(random.randrange(cfg["printer_cnt"])))
  row.append(fake.file_path(depth=3))
  row.append("print")
  row.append(abs(int(random.gauss(1000, 10000))))
  return row


# COMMAND ----------

# DBTITLE 1,Define the schemas for the data

file_schema = StructType()\
  .add("ts", TimestampType(), True)\
  .add("userid", StringType(), True)\
  .add("pc", StringType(), True)\
  .add("filename", StringType(), True)\
  .add("activity", StringType(), True)\
  .add("to_media", StringType(), True)\
  .add("from_media", StringType(), True)\
  .add("file_size", LongType(), True)

email_schema = StructType()\
  .add("ts", TimestampType(), True)\
  .add("userid", StringType(), True)\
  .add("pc", StringType(), True)\
  .add("to", StringType(), True)\
  .add("cc", StringType(), True)\
  .add("bcc", StringType(), True)\
  .add("from", StringType(), True)\
  .add("activity", StringType(), True)\
  .add("email_size", LongType(), True)\
  .add("attachment_size", LongType(), True)

web_schema = StructType()\
  .add("ts", TimestampType(), True)\
  .add("userid", StringType(), True)\
  .add("pc", StringType(), True)\
  .add("url", StringType(), True)\
  .add("activity", StringType(), True)\
  .add("size_in_bytes", LongType(), True)

print_schema = StructType()\
  .add("ts", TimestampType(), True)\
  .add("userid", StringType(), True)\
  .add("pc", StringType(), True)\
  .add("printer", StringType(), True)\
  .add("document_name", StringType(), True)\
  .add("activity", StringType(), True)\
  .add("print_size", LongType(), True)

# COMMAND ----------

# DBTITLE 1,Create the config for data generation

fake = Faker()
Faker.seed(0)
random.seed(1)

cfg["tmpdir"] = f"/dbfs/tmp/{cfg['db']}"
cfg["schemas"] = {
  "file": file_schema,
  "email": email_schema,
  "web": web_schema,
  "print": print_schema
}
cfg["user_cnt"] = 100
users = []  
for _ in range(cfg["user_cnt"]):
  rec = generate_user_tuple()
  users.append(rec)
cfg["users"] = users
cfg["userids"] = [ r[2] for r in users ]
cfg["pc_cnt"] = 2 * cfg["user_cnt"]
cfg["printer_cnt"] = int(0.2 * cfg["user_cnt"])
cfg["prob_file"] = 0.6
cfg["file_activity_list"] = ["copy", "delete", "open", "write"]
cfg["prob_email"] = 0.6
cfg["user_emails"] = [ r[1] for r in cfg["users"] ]
cfg["ext_emails"] = [ fake.ascii_email() for _ in range(2*cfg["user_cnt"]) ]
cfg["all_emails"] = [ e for e in cfg["user_emails"] ]
cfg["all_emails"].extend(cfg["ext_emails"])
cfg["prob_web"] = 0.6
cfg["web_activity_list"] = ["download", "upload", "visit"]
cfg["prob_print"] = 0.3
cfg["start_ts"] = datetime(2019, 1, 1, 0, tzinfo=timezone.utc)
cfg["end_ts"] = datetime(2021, 1, 1, 0, tzinfo=timezone.utc)
cfg["sim_unit_min"] = 60
cfg["batch_size_days"] = 10

# COMMAND ----------

# DBTITLE 1,Generate the data as CSV files on DBFS

os.makedirs(cfg["tmpdir"], exist_ok=True)
spark.sql(f"drop database if exists {cfg['db']} cascade")
spark.sql(f"create database if not exists {cfg['db']}")
spark.sql(f"use schema {cfg['db']}")

simulate_user_activity(cfg)


# COMMAND ----------

# DBTITLE 1,Load CSV files into delta tables
for data_type in cfg["schemas"].keys():
    tablename = cfg["db"] + "." + data_type
    csvfile = os.path.join("/tmp",cfg["db"], data_type + ".csv")
    df = spark.read.format("csv").option("header", "false").schema(cfg["schemas"][data_type]).load(csvfile)
    df.write.option("mergeSchema", "true").mode("overwrite").saveAsTable(tablename)

# COMMAND ----------

# MAGIC %sql
# MAGIC
# MAGIC select 'email' as tablename, count(*) as cnt
# MAGIC from email
# MAGIC union all
# MAGIC select 'web' as tablename, count(*) as cnt
# MAGIC from web
# MAGIC union all 
# MAGIC select 'print' as tablename, count(*) as cnt
# MAGIC from print
# MAGIC union all 
# MAGIC select 'file' as tablename, count(*) as cnt
# MAGIC from file

# COMMAND ----------

# MAGIC %sql
# MAGIC select * from email

# COMMAND ----------


