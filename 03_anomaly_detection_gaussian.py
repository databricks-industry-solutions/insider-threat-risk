# Databricks notebook source
# MAGIC %md
# MAGIC
# MAGIC # Statistics-based Anomaly Detection for Insider Data Exfiltration
# MAGIC
# MAGIC There are two different cases in data exfiltration incidents:
# MAGIC * Case 1: big data dump in a single event ("loud and proud")
# MAGIC * Case 2: small data dumps over multiple events over longer periods of time ("low and slow")
# MAGIC
# MAGIC Case 1 is obviously the easy case to detect and is well handled by the detection rules in current systems/technology.
# MAGIC Case 2 is much hard to detect and is the focus of this notebook.
# MAGIC
# MAGIC ![usecase_image](https://raw.githubusercontent.com/lipyeowlim/public/main/img/insider-threat/insider_threat_risk_gaussian.png)
# MAGIC
# MAGIC This solution accelerator will NOT cover the data ingestion and processing pipelines - it will assume that the data at the silver level in the diagram above is already available.
# MAGIC
# MAGIC ## Assumptions
# MAGIC * Data can be exfiltrated in multiple modalities: electronically (emails, http, etc.) or copied to removable media or printed to hardcopies
# MAGIC * Every individual is different in their routine and usage patterns - we want individual profiles/models
# MAGIC * The insider threat actor can and will spread their exfiltration tasks over multiple modalities to hide their tracks
# MAGIC
# MAGIC ## Overview of the anomaly detection method
# MAGIC
# MAGIC * Build statistical baselines based on the previous year for each individual
# MAGIC * For each individual, we model the baseline profile for each exfiltration modality (email, http, file etc.) with a Gaussian model (mean and standard deviation) extracted from the previous year data. Other distributions can certainly be used as well.
# MAGIC * For each exfiltration modality, we model the behavior as a weekly count/profile of some exfiltration event (which in itself can be a normal behavior).
# MAGIC * For each individual, an anomaly is when the weekly profile exceeds three standard deviations from the individual's baseline.
# MAGIC * The anomaly detection will use the previous years (tumbling window) baselines. For example, all the weekly profile for 2023 will be compared against the baselines for 2022.
# MAGIC * We do fusion of the anomalies in multiple modalities for an individual to mitigate threat actors masking their tracks with spreading their exfiltration task across different modalities.
# MAGIC
# MAGIC You have a choice of using either views or materialized views/tables for the baselines. Materialized views will be more performant at query time at the cost of table creation and maintenance. We use views below to demonstrate the flexibility and scalability of the platform.
# MAGIC
# MAGIC ## Background on the Gaussian or Normal Distribution
# MAGIC
# MAGIC * Many uni-modal & symmetric real world data distributions can be approximated by the Normal distribution. 
# MAGIC * The standard deviation in a Normal distribution is an measure of deviation from a mean. Hence the mean can be thought of as a "baseline". The following diagram shows how the standard deviation (represented by the greek letter sigma) relates the the rareness of an value on the x-axis. For example a value that is greater than the mean plus 3 sigmas has a probability 0.001 of occurring - very rare.
# MAGIC
# MAGIC ![usecase_image](https://raw.githubusercontent.com/lipyeowlim/public/main/img/insider-threat/gaussian.png)
# MAGIC
# MAGIC
# MAGIC ## Use case scenarios
# MAGIC
# MAGIC * Anomaly alerting on a weekly cadence
# MAGIC * Periodic hunts of users with anomalous/suspicious exfiltration behavior over a long time range
# MAGIC

# COMMAND ----------

# MAGIC %run ./config/notebook_config

# COMMAND ----------

spark.sql(f"use schema {cfg['db']}")

# COMMAND ----------

# MAGIC %md
# MAGIC
# MAGIC # File copies to external media

# COMMAND ----------

# DBTITLE 1,Create the view for weekly profiles
# MAGIC %sql
# MAGIC
# MAGIC drop view if exists v_weekly_file;
# MAGIC create view if not exists v_weekly_file 
# MAGIC as
# MAGIC select userid, date_trunc('YEAR', ts) as ts_year, date_trunc('WEEK', ts) as ts_week, sum(file_size) as weekly_file_size
# MAGIC from file
# MAGIC where to_media = 'True' and activity in ('write', 'copy')
# MAGIC group by userid, ts_year, ts_week;

# COMMAND ----------

# DBTITLE 1,Sanity check the weekly view
# MAGIC %sql
# MAGIC
# MAGIC select * from v_weekly_file;

# COMMAND ----------

# DBTITLE 1,Baselines for removable media file write events
# MAGIC %sql
# MAGIC
# MAGIC drop view if exists v_file_baselines;
# MAGIC create view if not exists v_file_baselines 
# MAGIC as
# MAGIC select userid, ts_year, avg(weekly_file_size) as avg_size, min(weekly_file_size) as min_size, max(weekly_file_size) as max_size, stddev(weekly_file_size) as std_dev
# MAGIC from v_weekly_file
# MAGIC group by userid, ts_year

# COMMAND ----------

# DBTITLE 1,Sanity check the baselines
# MAGIC %sql
# MAGIC
# MAGIC select *
# MAGIC from v_file_baselines
# MAGIC order by userid, ts_year;

# COMMAND ----------

# DBTITLE 1,Removable Media Write Anomalies
# MAGIC %sql
# MAGIC
# MAGIC drop view if exists v_file_anomalies;
# MAGIC
# MAGIC create view if not exists v_file_anomalies
# MAGIC as
# MAGIC select f.userid, f.ts_week, f.weekly_file_size, b.avg_size, b.std_dev, b.avg_size + 3*b.std_dev as threshold
# MAGIC from v_weekly_file as f 
# MAGIC   join v_file_baselines as b on f.userid = b.userid and b.ts_year = f.ts_year - '1 year'::interval
# MAGIC where f.weekly_file_size > b.avg_size + 3*b.std_dev
# MAGIC -- the ts_year filter is to ensure there enough data for a baseline

# COMMAND ----------

# DBTITLE 1,Sanity check the anomalies
# MAGIC %sql
# MAGIC
# MAGIC select *
# MAGIC from v_file_anomalies

# COMMAND ----------

# MAGIC %md
# MAGIC
# MAGIC # Email

# COMMAND ----------

# DBTITLE 1,Create the view for weekly profiles
# MAGIC %sql
# MAGIC
# MAGIC drop view if exists v_weekly_email;
# MAGIC create view if not exists v_weekly_email 
# MAGIC as
# MAGIC select userid, date_trunc('YEAR', ts) as ts_year, date_trunc('WEEK', ts) as ts_week, sum(email_size + attachment_size) as weekly_email_size
# MAGIC from 
# MAGIC   (
# MAGIC     select *, explode(split(`to`, ';')) as recv
# MAGIC     from email
# MAGIC   )
# MAGIC where not recv like '%xyz.com%'
# MAGIC group by userid, ts_year, ts_week;

# COMMAND ----------

# DBTITLE 1,Baselines for external-outbound email attachment sizes
# MAGIC %sql
# MAGIC
# MAGIC drop view if exists v_email_baselines;
# MAGIC create view if not exists v_email_baselines 
# MAGIC as
# MAGIC select userid, ts_year, avg(weekly_email_size) as avg_size, min(weekly_email_size) as min_size, max(weekly_email_size) as max_size, stddev(weekly_email_size) as std_dev
# MAGIC from v_weekly_email
# MAGIC group by userid, ts_year

# COMMAND ----------

# DBTITLE 1,Sanity check the baselines
# MAGIC %sql
# MAGIC
# MAGIC select *
# MAGIC from v_email_baselines
# MAGIC order by userid, ts_year;

# COMMAND ----------

# DBTITLE 1,External-Outbound Email Attachment Size Anomalies 
# MAGIC %sql
# MAGIC
# MAGIC drop view if exists v_email_anomalies;
# MAGIC
# MAGIC create view if not exists v_email_anomalies
# MAGIC as
# MAGIC select f.userid, f.ts_week, f.weekly_email_size, b.avg_size, b.std_dev, b.avg_size + 3*b.std_dev as threshold
# MAGIC from v_weekly_email as f 
# MAGIC   join v_email_baselines as b on f.userid = b.userid and b.ts_year = f.ts_year - '1 year'::interval
# MAGIC where f.weekly_email_size > b.avg_size + 3*b.std_dev
# MAGIC

# COMMAND ----------

# DBTITLE 1,Sanity check the anomalies
# MAGIC %sql
# MAGIC
# MAGIC select *
# MAGIC from v_email_anomalies

# COMMAND ----------

# MAGIC %md
# MAGIC
# MAGIC # Web uploads

# COMMAND ----------

# DBTITLE 1,Create the view for weekly profiles
# MAGIC %sql
# MAGIC
# MAGIC drop view if exists v_weekly_http;
# MAGIC create view if not exists v_weekly_http 
# MAGIC as
# MAGIC select userid, date_trunc('YEAR', ts) as ts_year, date_trunc('WEEK', ts) as ts_week, sum(size_in_bytes) as weekly_web_size
# MAGIC from web
# MAGIC where activity in ('upload')
# MAGIC group by userid, ts_year, ts_week

# COMMAND ----------

# DBTITLE 1,Baselines for HTTP upload events
# MAGIC %sql
# MAGIC
# MAGIC drop view if exists v_http_baselines;
# MAGIC create view if not exists v_http_baselines 
# MAGIC as
# MAGIC select userid, ts_year, avg(weekly_web_size) as avg_size, min(weekly_web_size) as min_size, max(weekly_web_size) as max_size, stddev(weekly_web_size) as std_dev
# MAGIC from v_weekly_http
# MAGIC group by userid, ts_year

# COMMAND ----------

# DBTITLE 1,Sanity check the baselines
# MAGIC %sql
# MAGIC
# MAGIC select *
# MAGIC from v_http_baselines
# MAGIC order by userid, ts_year;

# COMMAND ----------

# DBTITLE 1,Web Upload Anomalies
# MAGIC %sql
# MAGIC
# MAGIC drop view if exists v_web_anomalies;
# MAGIC
# MAGIC create view if not exists v_web_anomalies
# MAGIC as
# MAGIC select f.userid, f.ts_week, f.weekly_web_size, b.avg_size, b.std_dev, b.avg_size + 3*b.std_dev as threshold
# MAGIC from v_weekly_http as f join v_http_baselines as b on f.userid = b.userid and b.ts_year = f.ts_year - '1 year'::interval
# MAGIC where f.weekly_web_size > b.avg_size + 3*b.std_dev;

# COMMAND ----------

# DBTITLE 1,Sanity check the anomalies
# MAGIC %sql
# MAGIC
# MAGIC select *
# MAGIC from v_web_anomalies;

# COMMAND ----------

# MAGIC %md
# MAGIC
# MAGIC # Print to hardcopy

# COMMAND ----------

# DBTITLE 1,Create the view for weekly profiles
# MAGIC %sql
# MAGIC
# MAGIC drop view if exists v_weekly_print;
# MAGIC create view if not exists v_weekly_print 
# MAGIC as
# MAGIC select userid, date_trunc('YEAR', ts) as ts_year, date_trunc('WEEK', ts) as ts_week, sum(print_size) as weekly_print_size
# MAGIC from print
# MAGIC where activity in ('print')
# MAGIC group by userid, ts_year, ts_week;

# COMMAND ----------

# DBTITLE 1,Baselines for print events
# MAGIC %sql
# MAGIC
# MAGIC drop view if exists v_print_baselines;
# MAGIC create view if not exists v_print_baselines 
# MAGIC as
# MAGIC select userid, ts_year, avg(weekly_print_size) as avg_size, min(weekly_print_size) as min_size, max(weekly_print_size) as max_size, stddev(weekly_print_size) as std_dev
# MAGIC from v_weekly_print
# MAGIC group by userid, ts_year

# COMMAND ----------

# DBTITLE 1,Sanity check the baselines
# MAGIC %sql
# MAGIC
# MAGIC select *
# MAGIC from v_print_baselines
# MAGIC order by userid, ts_year

# COMMAND ----------

# DBTITLE 1,Print to hardcopy anomalies
# MAGIC %sql
# MAGIC
# MAGIC drop view if exists v_print_anomalies;
# MAGIC
# MAGIC create view if not exists v_print_anomalies
# MAGIC as
# MAGIC select f.userid, f.ts_week, f.weekly_print_size, b.avg_size, b.std_dev, b.avg_size + 3*b.std_dev as threshold
# MAGIC from v_weekly_print as f join v_print_baselines as b on f.userid = b.userid and b.ts_year = f.ts_year - '1 year'::interval
# MAGIC where f.weekly_print_size > b.avg_size + 3*b.std_dev;

# COMMAND ----------

# DBTITLE 1,Sanity check the anomalies
# MAGIC %sql
# MAGIC
# MAGIC select * from v_print_anomalies;

# COMMAND ----------

# MAGIC %md
# MAGIC
# MAGIC # Fusion Insider Risk Scoring
# MAGIC
# MAGIC * This will help catch threat actors that try to spread their exfiltration load across multiple modalities
# MAGIC * The weights will need to be tuned for the specific organizational environment
# MAGIC * This risk scoring can be re-evaluated weekly based on the entire history or using a window of historical data. Risk scores above a threshold can trigger an alert to be triage by an analyst.
# MAGIC * The following query evaluates the risk scores as of 2021-01-01 over a 6-month window.

# COMMAND ----------


scoring_ts = '2021-01-01'
scoring_window = '6 months'
sql_str = f"""
select userid, anomaly_score, map_from_arrays(a_types, a_cnts) as details
from (
  select userid, sum(wt_anomaly_cnt) as anomaly_score, array_agg(anomaly_type) as a_types, array_agg(anomaly_cnt) as a_cnts
  from
  (
    select userid, anomaly_type, anomaly_cnt, 1.0 * anomaly_cnt as wt_anomaly_cnt
    from ( 
      select 'file' as anomaly_type, userid, count(*) as anomaly_cnt
      from v_file_anomalies
      where ts_week between '{scoring_ts}'::timestamp - '{scoring_window}'::interval and '{scoring_ts}'::timestamp
      group by userid
    )
    union all
    select userid, anomaly_type, anomaly_cnt, 0.3 * anomaly_cnt as wt_anomaly_cnt
    from ( 
      select 'email' as anomaly_type, userid, count(*) as anomaly_cnt
      from v_email_anomalies
      where ts_week between '{scoring_ts}'::timestamp - '{scoring_window}'::interval and '{scoring_ts}'::timestamp
      group by userid
    )
    union all
    select userid, anomaly_type, anomaly_cnt, 0.5 * anomaly_cnt as wt_anomaly_cnt
    from ( 
      select 'web' as anomaly_type, userid, count(*) as anomaly_cnt
      from v_web_anomalies
      where ts_week between '{scoring_ts}'::timestamp - '{scoring_window}'::interval and '{scoring_ts}'::timestamp
      group by userid
    )
    union all
    select userid, anomaly_type, anomaly_cnt, 0.5 * anomaly_cnt as wt_anomaly_cnt
    from ( 
      select 'print' as anomaly_type, userid, count(*) as anomaly_cnt
      from v_print_anomalies
      where ts_week between '{scoring_ts}'::timestamp - '{scoring_window}'::interval and '{scoring_ts}'::timestamp
      group by userid
    )
  )
  group by userid
  order by anomaly_score desc
  limit 20
)
"""

df = spark.sql(sql_str)
display(df)

# COMMAND ----------


