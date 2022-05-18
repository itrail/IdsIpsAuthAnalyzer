import mysql.connector
from packages.config import mysql_config


def create_cursor():
    mydb = mysql.connector.connect(**mysql_config)
    mycursor = mydb.cursor()
    return mydb, mycursor


def insert_data(mydb, mycursor, query, data_list):
    mycursor.executemany(query, data_list)
    mydb.commit()
    return
