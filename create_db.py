import mysql.connector
import os
from dotenv import load_dotenv

load_dotenv()

mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  passwd="Family6104$"
)

my_cursor=mydb.cursor()

# my_cursor.execute("CREATE DATABASE login")

my_cursor.execute("SHOW DATABASES")
for db in my_cursor:
  print(db)