from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from commitdb.postgres import PostgresCommitDB
from util.config_parser import parse_config_file
config = parse_config_file(

db = PostgresCommitDB(
     config.database.user,
     config.database.password,
     config.database.host,
     config.database.port,
     config.database.dbname,
)
db.connect()
db.reset()
