![image](https://github.com/lipyeowlim/public/raw/main/img/logo/databricks_cyber_logo_v1.png)

[![CLOUD](https://img.shields.io/badge/CLOUD-ALL-blue?logo=googlecloud&style=for-the-badge)](https://cloud.google.com/databricks)
[![POC](https://img.shields.io/badge/POC-10_days-green?style=for-the-badge)](https://databricks.com/try-databricks)

# Insider Threat Detection & Risk Scoring

Contact Author: <cybersecurity@databricks.com>

## Use Cases

* Detect insider data exfiltration threat using per-user anomaly detection models
* Detect compromises of service principals or service accounts in cloud security
* Risk scoring of data exfiltration likelihood of each user

## Reference Architecture

![usecase_image](https://raw.githubusercontent.com/lipyeowlim/public/main/img/insider-threat/insider_threat_risk_architecture.png)

This solution accelerator will focus on the anomaly detection and risk scoring aspects and will not cover the data ingestion and pre-processing pipelines.

## Technical Overview

* Generate & load different data sets (file, email, web, print) into the lakehouse
* Create baseline models for each user and each data source (exfiltration modality)
    * Statistical baselines using Normal distribution
    * Anomaly detection using the 40+ algorithms from the Python Outlier Detection (PyOD) library.
* Anomaly detection using the baselines/models for each user and data source
* Fuse different signals to produce a risk score
___

&copy; 2022 Databricks, Inc. All rights reserved. The source in this notebook is provided subject to the Databricks License [https://databricks.com/db-license-source].  All included or referenced third party libraries are subject to the licenses set forth below.

| library                                | description             | license    | source                                              |
|----------------------------------------|-------------------------|------------|-----------------------------------------------------|
| Faker | Generate fake values | MIT        | https://github.com/joke2k/faker                     |
| PyOD | Python Outlier Detection | BSD-2-Clause | https://github.com/yzhao062/pyod |

## Getting started

Although specific solutions can be downloaded as .dbc archives from our websites, we recommend cloning these repositories onto your databricks environment. Not only will you get access to latest code, but you will be part of a community of experts driving industry best practices and re-usable solutions, influencing our respective industries. 

<img width="500" alt="add_repo" src="https://user-images.githubusercontent.com/4445837/177207338-65135b10-8ccc-4d17-be21-09416c861a76.png">

To start using a solution accelerator in Databricks simply follow these steps: 

1. Clone solution accelerator repository in Databricks using [Databricks Repos](https://www.databricks.com/product/repos)
2. Attach the `RUNME` notebook to any cluster and execute the notebook via Run-All. A multi-step-job describing the accelerator pipeline will be created, and the link will be provided. The job configuration is written in the RUNME notebook in json format. 
3. Execute the multi-step-job to see how the pipeline runs. 
4. You might want to modify the samples in the solution accelerator to your need, collaborate with other users and run the code samples against your own data. To do so start by changing the Git remote of your repository  to your organization’s repository vs using our samples repository (learn more). You can now commit and push code, collaborate with other user’s via Git and follow your organization’s processes for code development.

The cost associated with running the accelerator is the user's responsibility.

## Project support 

Please note the code in this project is provided for your exploration only, and are not formally supported by Databricks with Service Level Agreements (SLAs). They are provided AS-IS and we do not make any guarantees of any kind. Please do not submit a support ticket relating to any issues arising from the use of these projects. The source in this project is provided subject to the Databricks [License](./LICENSE). All included or referenced third party libraries are subject to the licenses set forth below.

Any issues discovered through the use of this project should be filed as GitHub Issues on the Repo. They will be reviewed as time permits, but there are no formal SLAs for support. 
