import pymongo
import logging
import json
from pymongo import MongoClient
from pymongo import errors as mongoerrors
from bson.json_util import dumps

def insert_data(client, database, column, data)-> tuple:
    dbclient = MongoClient(client)
    db = dbclient[database]
    dbcol = db[column]
    try:
        dbcol.insert(data)
    except mongoerrors.PyMongoError as e:
        logging.exception(e)
        return False, e
    return True, None


def get_data(client, database, coloumn, query)-> tuple:
    dbclient = MongoClient(client)
    db = dbclient[database]
    dbcol = db[coloumn]
    try:
        alldata = json.loads(dumps(dbcol.find(query)))
    except mongoerrors.PyMongoError as e:
        logging.exception(e)
        return False, e
    return True, alldata