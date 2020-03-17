import datetime

from pony.orm import *


db = Database()


class User(db.Entity):
    user_id = PrimaryKey(str)
    user_name = Required(str)
    user_events = Set('Hours')

    
class Tag(db.Entity):
    tag_id = PrimaryKey(str)
    location = Optional(str)
    tag_key = Required(str)
    tag_events = Set('Hours')
    
    
class Hours(db.Entity):
    event_id = PrimaryKey(int, auto=True)
    timestamp = Required(datetime.datetime)
    tag_id = Required(Tag)
    user_id = Required(User)
    
    
if __name__ == '__main__':
    db.bind(provider='mysql', host='localhost', user='navig01_nfcroot', passwd='AQqBRMqQ&D8?wZNA', db='navig01_nfcwork')    
    db.generate_mapping(create_tables=True)