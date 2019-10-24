import pymongo
import logging
from pymongo import MongoClient
from pymongo import errors as mongoerrors

def insert_data(client, database, coloumn, data)-> bool:
    dbclient = MongoClient(client)
    db = dbclient[database]
    dbcol = db[coloumn]
    try:
        dbcol.insert_many(data)
    except mongoerrors.PyMongoError as e:
        logging.exception(e)
        return False
    return True
