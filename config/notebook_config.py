# Databricks notebook source
# MAGIC %md
# MAGIC
# MAGIC ## Setup Configuration

# COMMAND ----------

import os
import json
import re

cfg={}
cfg["useremail"] = dbutils.notebook.entry_point.getDbutils().notebook().getContext().userName().get()
cfg["username"] = cfg["useremail"].split('@')[0]
cfg["username_sql_compatible"] = re.sub('\W', '_', cfg["username"])
cfg["db"] = f"insider_{cfg['username_sql_compatible']}"

if "getParam" not in vars():
  def getParam(param):
    assert param in cfg
    return cfg[param]

print(json.dumps(cfg, indent=2))


# COMMAND ----------


