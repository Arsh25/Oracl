import pymongo
import logging
from pymongo import MongoClient
from pymongo import errors as mongoerrors

def insert_data(client, database, coloumn, data)-> tuple:
    dbclient = MongoClient(client)
    db = dbclient[database]
    dbcol = db[coloumn]
    try:
        dbcol.insert_many(data)
    except mongoerrors.PyMongoError as e:
        logging.exception(e)
        return False, e
    return True, None


def get_data(client, database, coloumn, data)-> tuple:
    dbclient = MongoClient(client)
    db = dbclient[database]
    dbcol = db[coloumn]
    try:
        alldata = dbcol.find(data)
    except mongoerrors.PyMongoError as e:
        logging.exception(e)
        return False, e
    return True, alldata