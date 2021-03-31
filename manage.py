from application import application, db
from flask_script import Manager
from flask_migrate import Migrate, MigrateCommand

migrate = Migrate(application, db)
manager = Manager(application)


# migrations
manager.add_command('db', MigrateCommand)


if __name__ == '__main__':
    manager.run()
