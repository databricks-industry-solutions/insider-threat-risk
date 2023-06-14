# Databricks notebook source
# MAGIC %md
# MAGIC
# MAGIC ![image](https://github.com/lipyeowlim/public/raw/main/img/logo/databricks_cyber_logo_v1.png)
# MAGIC
# MAGIC # Insider Threat Risk 
# MAGIC
# MAGIC ## What is an "insider threat" (cf. external threat)?
# MAGIC
# MAGIC An insider threat is the potential for an insider to use their authorized access or understanding of an organization to harm that organization. There are 3 categories of insider threats:
# MAGIC * Unintentional
# MAGIC   * Negligence
# MAGIC   * Accidental
# MAGIC * Intentional (“malicious insider”)
# MAGIC * Other threats
# MAGIC   * Collusive Threats
# MAGIC   * Third-Party Threats
# MAGIC
# MAGIC Note also that the lines between an insider threat and an external threats are blurring. External threats where an attacker steals the credentials of an insider and impersonates the insider will initially appear to the cybersecurity defenders like an "insider threat".
# MAGIC
# MAGIC Source: https://www.cisa.gov/topics/physical-security/insider-threat-mitigation/defining-insider-threats
# MAGIC
# MAGIC ## Per user-modality anomaly detection models
# MAGIC
# MAGIC This solution accelerator leverages the scalability of the Databricks Lakehouse platform to perform user behavior modeling at the per user, per modality granularity and uses those models for anomaly detection.
# MAGIC
# MAGIC * `03_anomaly_detection_gaussian.py` uses a statistical gaussian model for each user-modality
# MAGIC * (WIP) k-means-based model
# MAGIC

# COMMAND ----------

# MAGIC %md
# MAGIC ## Reference Architecture
# MAGIC
# MAGIC This architecture shows how the insider threat risk scoring will fit into a the bigger picture of a cybersecurity lakehouse.
# MAGIC
# MAGIC ![usecase_image](https://raw.githubusercontent.com/lipyeowlim/public/main/img/insider-threat/insider_threat_risk_architecture.png)
# MAGIC
# MAGIC This solution accelerator will focus on the anomaly detection and risk scoring aspects and will not cover the in depth data ingest and pre-processing pipelines.
# MAGIC

# COMMAND ----------


