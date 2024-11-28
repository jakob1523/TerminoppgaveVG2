from app import app, db

# This will create the tables based on your models
with app.app_context():
    db.create_all()
    print("Database tables created successfully!")