from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User

# Connect to Database and create database session
engine = create_engine('sqlite:///catalogwithusers.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

# User
user1 = User(
    name="John Smith",
    email="email@place.com",
    picture="http://www.diaglobal.org/_Images/member/Generic_Image_Missing-Profile.jpg"
)
session.add(user1)
session.commit()

# Category
category1 = Category(name="Snowboarding")
session.add(category1)
session.commit()

# Items
item1 = Item(
    name="Helmet",
    description="Protective item for your head.",
    category_id=1,
    user_id=1
)
session.add(item1)
session.commit()

item2 = Item(
    name="Snowpants",
    description="Warm pants to keep you dry.",
    category=category1,
    user=user1
)
session.add(item2)
session.commit()

# Category
category1 = Category(name="Soccer")
session.add(category1)
session.commit()

# Category
category1 = Category(name="Basketball")
session.add(category1)
session.commit()

# Category
category1 = Category(name="Baseball")
session.add(category1)
session.commit()

# Category
category1 = Category(name="Rock Climbing")
session.add(category1)
session.commit()

# Category
category1 = Category(name="Frisbee")
session.add(category1)
session.commit()

print "Added to database!"