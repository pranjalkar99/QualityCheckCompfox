from google.cloud import storage
from google.oauth2 import service_account
import os
import uuid
import json
import random
import logging
## logger config
# Create and configure logger
logging.basicConfig(filename="newfile.log",
                    format='%(asctime)s %(message)s',
                    filemode='w')
 
# Creating an object
logger = logging.getLogger()
 
# Setting the threshold of logger to DEBUG
logger.setLevel(logging.DEBUG)

##
# from pyloggers import CONSOLE


def get_id():
   id = uuid.uuid1()
   return str(id)



storage_cleint = storage.Client.from_service_account_json('compfox-367313-ad58ca97af3b.json')
def name_split(filename):
    # split the filename by underscore
    parts = filename.split('_')

    # extract the required substring
    name = parts[3][:-4]
    return name
async def get_first_100():
    bucket_name = "regular_final_html"
    filenames=[]
    count=0
    # Get a reference to the bucket
    bucket = storage_cleint.get_bucket(bucket_name)
    # List all HTML files in the bucket
    data={}
    dict_list={}
    pages=[]
    blobs = bucket.list_blobs(prefix="", delimiter="/")
    for blob in blobs:
        count+=1
        if count<=100:
            if blob.name.endswith('.pdf'):
                print(blob.name, "count:",count)
                name = name_split(blob.name)
                filenames.append(name)
                html_blob = bucket.blob(blob.name)
                html_contents = html_blob.download_as_string().decode("utf-8")
                logger.debug(" The html is as follows: {} --DONE".format(html_contents))
                # print(html_contents)
                # exit()
                id=get_id()
                data[id]={}
                data[id]['filename']=name
                data[id]['status']='default'
                my_dict = json.loads(html_contents)
                data[id]['html']=my_dict
        else:
            break
    
    json_data = json.dumps(data)
    with open('db4_data.json', 'w') as f:
        f.write(json_data)
    return "done"



def get_json():
#client = storage.Client(Credentials=google_credentials)
    bucket_name = "regular_final_html"

    # Get a reference to the bucket
    bucket = storage_cleint.get_bucket(bucket_name)
    # List all HTML files in the bucket
    blobs = bucket.list_blobs(prefix="", delimiter="/")
    filenames = []
    dict_list = []
    keys = []
    data = {}
    for blob in blobs:
        if blob.name.endswith('.pdf'):
            name = name_split(blob.name)
            filenames.append(name)
            html_blob = bucket.blob(blob.name)
            html_contents = html_blob.download_as_string().decode("utf-8")
            my_dict = json.loads(html_contents)
            for key, value in my_dict.items():
                # print(key)
                keys.append(key)
                id = random.randint(0,10000)
                data[id] = {"text": value, "filename":name}
        if len(keys) >100:
            dict_list.append(data)
            data = {}
            keys = []
    # convert the list to JSON
    json_data = json.dumps(dict_list)

    # save the JSON data to a file
    with open('db4_data.json', 'w') as f:
        f.write(json_data)
    with open('list_of_left.txt','w') as p:
        p.write(filenames)

    
def load_db():
    if os.path.isfile("db4_data.json"):
        duck=open("db4_data.json","r")
        return duck.read()
    else:
        logger.error("Not found db in load_db function...")
        return "Not found db."
        