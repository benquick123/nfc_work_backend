import json
from datetime import datetime, timedelta
from dateutil.relativedelta import *
import base64
import os

import web
from pony.orm import *
import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

from db import User, Tag, Hours, db


urls = (
  '/send_nfc_event', 'send_nfc_event',
  '/manage_hours', 'manage_hours',
  '/manage_users', 'manage_users',
  '/manage_tags', 'manage_tags'
)


class manage_tags:
    @db_session
    def POST(self):
        web.header('Content-Type', 'application/json')
        data = json.loads(web.data())
        if 'tag_id' not in data:
            return json.dumps({'response': "404, but not really", 'message': "missing tag_id"})
        
        password_secret = "moja_mami"
        password = data['tag_id'] + password_secret
        password = password.encode()
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        string_key = key.decode("utf-8")

        if 'location' in data:
            new_tag = Tag(tag_id=data['tag_id'], location=data['location'], tag_key=string_key)
        else:
            new_tag = Tag(tag_id=data['tag_id'], tag_key=string_key)

        return json.dumps({'response': "SAVE SUCCESS.", 'new_tag': str(new_tag)})
    
    def DELETE(self):
        web.header('Content-Type', 'application/json')
        return json.dumps({'response': "NOT IMPLEMENTED."})


class manage_users:
    @db_session
    def GET(self):
        web.header('Content-Type', 'application/json')
        query = web.ctx.query
        query = query.replace('?', '').split('&')
        if len(query) != 1:
            return json.dumps({'response': "404, but not really", 'message': "wrong number of arguments."})
        
        query_dict = dict([field.split("=") for field in query])
        
        if 'user_name' not in query_dict and 'user_id' not in query_dict:
            return json.dumps({'response': "404, but not really", 'message': "either user_name or user_id must be specified."})
        
        query_by = 'user_name' if 'user_name' in query_dict else 'user_id'
        user = select(u for u in User if u.user_name == query_dict[query_by] or u.user_id == query_dict[query_by])[:]
        
        return json.dumps({'response': "SEARCH EXECUTED.", 'data': str([u.to_dict() for u in user])})
    
    @db_session
    def POST(self):
        web.header('Content-Type', 'application/json')
        data = json.loads(web.data())
        if 'user_id' not in data or 'user_name' not in data:
            return json.dumps({'response': "404, but not really", 'message': "missing user_id or user_name"})
        
        new_user = User(user_id=data['user_id'], user_name=data['user_name'])
        
        return json.dumps({'response': "SAVE SUCCESS.", 'new_tag': str(new_user)})
    
    def DELETE(self):
        web.header('Content-Type', 'application/json')
        return json.dumps({'response': "NOT IMPLEMENTED."})


class send_nfc_event:
    @db_session
    def POST(self):
        web.header('Content-Type', 'application/json')
        data = json.loads(web.data())
        if 'user_id' not in data or 'tag_id' not in data:
            return json.dumps({'response': "404, but not really", 'message': "missing user_id or tag_id"})
        
        if 'cipher' not in data:
            return json.dumps({'response': "404, but not really", 'message': "missing cipher"})
        
        
        
        user = select(u for u in User if u.user_id == data['user_id'])[:]
        tag = select(t for t in Tag if t.tag_id == data['tag_id'])[:]
        
        if len(user) == 0:
            return json.dumps({'response': "404, but not really", 'message': "user with id " + str(data['user_id']) + " does not exist."})
        if len(tag) == 0:
            return json.dumps({'response': "404, but not really", 'message': "tag with id " + str(data['tag_id']) + " does not exist."})
        
        if tag[0].tag_key == data['cipher']:
            timestamp = datetime.now()
            
            date_start = datetime(timestamp.year, timestamp.month, timestamp.day, 0, 0, 0)
            date_end = date_start + relativedelta(hours=24)
            hours = select(h for h in Hours if h.user_id == user[0] and h.timestamp >= date_start and h.timestamp < date_end).order_by(Hours.timestamp)[:]
            
            timediff = ""
            if len(hours) % 2 == 1:
                timediff = timestamp - hours[-1].timestamp
                add_hours = timediff.seconds // 3600
                add_minutes = (timediff.seconds % 3600) / 60
                timediff = "+%02d:%02d" % (add_hours, add_minutes)
            
            if len(hours) > 0 and hours[-1].timestamp + timedelta(minutes=1) > timestamp:
                return json.dumps({'response': "SUCCESS", "timestamp": str(timestamp), 'type': 'arrive' if len(hours) % 2 == 1 else 'leave', 'message': 'timestamps too close together', "timediff": timediff})
            
            new_event = Hours(timestamp=timestamp, tag_id=tag[0], user_id=user[0])
            # watch out for reversed event_type logic
            return json.dumps({'response': "SUCCESS", "type": 'arrive' if len(hours) % 2 == 0 else 'leave', "timestamp": str(timestamp), "timediff": timediff})
        else:
            return json.dumps({'response': "404, but not really", 'message': "AUTHENTICATION FAILURE."})
    
    
class manage_hours:
    @db_session
    def POST(self):
        web.header('Content-Type', 'application/json')
        data = json.loads(web.data())
        if 'user_id' not in data or 'tag_id' not in data:
            return json.dumps({'response': "404, but not really", 'message': "missing user_id or tag_id"})
        
        user = select(u for u in User if u.user_id == data['user_id'])[:]
        tag = select(t for t in Tag if t.tag_id == data['tag_id'])[:]
        
        if 'timestamp' not in data:
            return json.dumps({'response': "404, but not really", 'message': "missing timestamp"})
        
        try:
            data['timestamp'] = datetime.strptime(data['timestamp'], '%Y-%m-%d-%H-%M-%S')
        except ValueError:
            return json.dumps({'response': "404, but not really", 'response': "incorrect data format. Expecting: 'YYYY-MM-DD-hh-mm-ss'."})
        
        new_event = Hours(timestamp=data['timestamp'], tag_id=tag[0], user_id=user[0])
        
        return json.dumps({'response': "SAVE SUCCESS.", 'new_event': str(new_event)})
    
    @db_session
    def GET(self):
        web.header('Content-Type', 'application/json')
        query = web.ctx.query
        query = query.replace('?', '').split('&')
        if len(query) < 3 or len(query) > 4:
            return json.dumps({'response': "404, but not really", 'message': "wrong number of arguments."})
        
        query_dict = dict([field.split('=') for field in query])
        if 'month' in query_dict or 'year' not in query_dict:
            try:
                query_dict['month'] = int(query_dict['month'])
                query_dict['year'] = int(query_dict['year'])
            except ValueError:
                return json.dumps({'response': "404, but not really", 'message': "month or year is not int."})
        else:
            return json.dumps({'response': "404, but not really", 'message': "month or year not in query."})
        
        
        if 'user_id' not in query_dict:
            return json.dumps({'response': "404, but not really", 'message': "user_id not specified."})
        
        user = select(u for u in User if u.user_id == query_dict['user_id'])[:]
        if len(user) == 0:
            return json.dumps({'response': "404, but not really", 'message': "user with id " + str(query_dict['user_id']) + " does not exist."})
        
        date_start = datetime(query_dict['year'], query_dict['month'], 1, 0, 0, 0)
        date_end = date_start + relativedelta(months=1)
        
        hours = select(h for h in Hours if h.user_id == user[0] and h.timestamp >= date_start and h.timestamp < date_end).order_by(Hours.timestamp)[:]
        hours = [h.to_dict() for h in hours]
        
        result = []
        i = 0
        while i < len(hours):
            arrive = hours[i]
            if len(hours) - 1 >= i + 1:
                leave = {'tag_id': hours[i+1]['tag_id'] if hours[i]['timestamp'].day == hours[i+1]['timestamp'].day else 'NA',
                         'timestamp': hours[i+1]['timestamp'] if hours[i]['timestamp'].day == hours[i+1]['timestamp'].day else datetime(arrive['timestamp'].year, arrive['timestamp'].month, arrive['timestamp'].day, 23, 59, 59)}
                timediff = leave['timestamp'] - arrive['timestamp']
                add_hours = timediff.seconds // 3600
                add_minutes = (timediff.seconds % 3600) // 60
                timediff = "%02d:%02d" % (add_hours, add_minutes)
            else:
                leave = {'tag_id': 'NA', 
                         'timestamp': 'NA' if hours[i]['timestamp'].day == datetime.now().day else datetime(arrive['timestamp'].year, arrive['timestamp'].month, arrive['timestamp'].day, 23, 59, 59)}
                if hours[i]['timestamp'].day == datetime.now().day:
                    timediff = "NA"
                else:
                    timediff = leave['timestamp'] - arrive['timestamp']
                    add_hours = timediff.seconds // 3600
                    add_minutes = (timediff.seconds % 3600) // 60
                    timediff = "%02d:%02d" % (add_hours, add_minutes)
                
            result.append({'user_id': arrive['user_id'], 
                           'arrive_tag': arrive['tag_id'], 
                           'leave_tag': leave['tag_id'], 
                           'arrive_timestamp': datetime.strftime(arrive['timestamp'], '%Y-%m-%d %H:%M:%S'), 
                           'leave_timestamp': datetime.strftime(leave['timestamp'], '%Y-%m-%d %H:%M:%S') if leave['timestamp'] != 'NA' else leave['timestamp'],
                           'timediff': timediff if timediff != 'NA' else timediff})
            
            try:
                i += 2 if hours[i]['timestamp'].day == hours[i+1]['timestamp'].day else 1
            except IndexError:
                break

        if 'format' in query_dict:
            if query_dict['format'] == 'csv':
                web.header('Content-Type', 'text/csv')
                web.header('Content-disposition', 'attachment; filename=export_hours_' + str(query_dict['month']) + '_' + str(query_dict['year']) + '.csv')
                csv = "user_id,arrive_tag,leave_tag,arrive_timestamp,leave_timestamp,timediff\n"
                for entry in result:
                    csv += ",".join([value for value in entry.values()]) + "\n"
                return csv
            else:
                return json.dumps({'response': "404, but not really", 'message': "format " + str(query_dict['format']) + " not supported"})
        else:
            return json.dumps({'response': 'SEARCH EXECUTED.', 'data': result})
    
    def DELETE(self):
        web.header('Content-Type', 'application/json')
        return json.dumps({'response': "NOT IMPLEMENTED."})



if __name__ == '__main__':
    db.bind(provider='mysql', host='localhost', user='navig01_nfcroot', passwd='AQqBRMqQ&D8?wZNA', db='navig01_nfcwork')
    db.generate_mapping(create_tables=True)
    app = web.application(urls, globals())
    app.run()
else:
    # uncomment this when deploying!
    db.bind(provider='mysql', host='localhost', user='navig01_nfcroot', passwd='AQqBRMqQ&D8?wZNA', db='navig01_nfcwork')
    db.generate_mapping(create_tables=True)
    application = web.application(urls, globals()).wsgifunc()