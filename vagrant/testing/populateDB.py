from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Restaurant, MenuItem

#Creates the link to the database via a session
engine = create_engine('sqlite:///restaurantmenu.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

#Add to the database via object like methods and commit to save entry
myFirstRestaurant = Restaurant(name="Pizza Palace")
session.add(myFirstRestaurant)
session.commit()

#Checks to see if the entry was saved to database
session.query(Restaurant).all()

cheesepizza = MenuItem(
    name="Cheese Pizza",
    description="Made with all natural ingredients and fresh mozzarella",
    course="Entree",
    price="$8.99",
    restaurant=myFirstRestaurant
)
session.add(cheesepizza)
session.commit()

session.query(MenuItem).all()

# Access all items in a query
# items = session.query(MenuItem).all()
# for item in items:
#     print item.name



# Filtering items
# veggieBurgers = session.query(MenuItem).filter_by(name = 'Veggie Burger')
# for veggieBurger in veggieBurgers:
#     print veggieBurger.id
#     print veggieBurger.price
#     print veggieBurger.restaurant.name
#     print "\n"



# Update values
# UrbanVeggieBurger = session.query(MenuItem).filter_by(id=8).one()
# UrbanVeggieBurger.price = '$2.99'
# session.add(UrbanVeggieBurger)
# session.commit()


# Delete items
# spinach = session.query(MenuItem).filter_by(name='Spinach Ice Cream').one()
# session.delete(spinach)
# session.commit()