from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Shelter, Puppy
import datetime
from dateutil import monthdelta

engine = create_engine('sqlite:///puppyshelter.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

# Query all of the puppies and return
# the results in ascending alphabetical order
for puppy in session.query(Puppy).order_by(Puppy.name):
    print puppy.name

