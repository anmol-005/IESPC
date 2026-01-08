# Influencer Engagement & Sponsorship Campaign Platform (IESCP)

The **Influencer Engagement & Sponsorship Campaign Platform (IESCP)** is a web-based application designed to connect **Sponsors** and **Influencers**. Sponsors can create and manage marketing campaigns, while influencers can discover opportunities, manage ad requests, and track collaborations.

> **Note:** This was one of my early projects (**MAD1**), so the architecture is **monolithic**, with most of the backend logic contained within a single `app.py` file.

---

## 🚀 Features

### 👔 For Sponsors
- **Campaign Management**  
  Create, edit, and delete sponsorship campaigns with defined budgets and niches.
- **Ad Requests**  
  Send private ad requests to specific influencers or create public requests.
- **Dashboard**  
  Track active campaigns and the status of ad requests (*Pending, Active, Completed*).

### 🌟 For Influencers
- **Discovery**  
  Search for public campaigns based on niche, category, or budget.
- **Request Management**  
  Accept or reject incoming sponsorship requests.
- **Work Verification**  
  Submit links to completed work and mark tasks as complete.
- **Profile Management**  
  Update reach, niche, and category details.

### 🛡️ For Admins
- **User Management**  
  Monitor all users and flag or delete accounts when necessary.
- **Campaign Monitoring**  
  Flag or remove inappropriate campaigns.
- **Statistics Dashboard**  
  View platform-wide metrics such as total users, active campaigns, and ad request statuses.

---

## 🛠️ Tech Stack

- **Backend:** Python, Flask  
- **Database:** SQLite with Flask-SQLAlchemy  
- **Frontend:** HTML, CSS (Bootstrap-based templates)  
- **Authentication:** Flask session-based login  

---

## 📋 Database Schema

The application uses three primary tables:

- **Users**  
  Stores credentials and profile details for Admins, Sponsors, and Influencers.
- **Campaigns**  
  Contains campaign information created by Sponsors.
- **AdRequests**  
  Manages the relationship between Campaigns and Influencers, including status and payment details.

---

## 🏃 Setup Instructions

### 1️⃣ Clone the Repository
```
git clone <your-repo-url>
cd <project-folder>
```

### 2️⃣ Set Up a Virtual Environment (Recommended)
```python -m venv venv

# On Windows
venv\Scripts\activate

# On macOS/Linux
source venv/bin/activate
```

### 3️⃣ Install Dependencies
```pip install flask flask-sqlalchemy sqlalchemy
```

### 4️⃣ Run the Application
```python app.py
```

The application will automatically seed demo data on the first run and start on:
http://127.0.0.1:10000

### 🔑 Demo Credentials
The following accounts are automatically created via the seed_data() function:
```| Role       | Email                                                   | Password  |
| ---------- | ------------------------------------------------------- | --------- |
| Admin      | [admin@example.com](mailto:admin@example.com)           | Admin@123 |
| Sponsor    | [sponsor@example.com](mailto:sponsor@example.com)       | Demo@123  |
| Influencer | [influencer@example.com](mailto:influencer@example.com) | Demo@123  |
```

### 📁 Project Structure
```.
├── app.py              # Core logic (Models, Routes, and Business Logic)
├── instance/
│   └── iescp.db        # SQLite database (generated at runtime)
├── templates/          # HTML files for all views
└── static/             # CSS / JS files (if any)
```
