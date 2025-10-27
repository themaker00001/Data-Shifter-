import customtkinter as ctk
from tkinter import messagebox
from PIL import Image
import sqlite3
import bcrypt
import pandas as pd
from sqlalchemy import create_engine, text
from pymongo import MongoClient
import os

# ------------------ DATABASE SETUP ------------------
def init_db(db_name="users.db"):
    conn = sqlite3.connect(db_name)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password BLOB NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def register_user(email, password, db_name="users.db"):
    conn = sqlite3.connect(db_name)
    cur = conn.cursor()
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    try:
        cur.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, hashed))
        conn.commit()
        messagebox.showinfo("Success", "✅ User registered successfully!")
    except sqlite3.IntegrityError:
        messagebox.showerror("Error", "❌ User already exists!")
    conn.close()

def verify_user(email, password, db_name="users.db"):
    conn = sqlite3.connect(db_name)
    cur = conn.cursor()
    cur.execute("SELECT password FROM users WHERE email=?", (email,))
    result = cur.fetchone()
    conn.close()
    if result and bcrypt.checkpw(password.encode('utf-8'), result[0]):
        return True
    return False

def ensure_default_admin():
    """Creates a default admin user if it doesn't exist."""
    conn = sqlite3.connect("users.db")
    cur = conn.cursor()
    cur.execute("SELECT email FROM users WHERE email='admin@demo.com'")
    exists = cur.fetchone()
    if not exists:
        hashed = bcrypt.hashpw("admin".encode('utf-8'), bcrypt.gensalt())
        cur.execute("INSERT INTO users (email, password) VALUES (?, ?)", ("admin@demo.com", hashed))
        conn.commit()
    conn.close()

# Initialize DB
init_db("users.db")
ensure_default_admin()

# ------------------ GLOBAL STATE ------------------
user_dvc_config = {
    "enabled": False,
    "type": None,      # "Local" or "Remote"
    "remote_path": ""
}

# ------------------ MIGRATION FUNCTIONS ------------------
def get_sql_engine(source_type, host=None, port=None, user=None, password=None, db_name=None):
    try:
        if source_type == "SQLite":
            if not db_name:
                raise ValueError("Provide SQLite file path as Database Name")
            conn_str = f"sqlite:///{db_name}"
        elif source_type == "SQL Server":
            conn_str = f"mssql+pyodbc://{user}:{password}@{host},{port}/{db_name}?driver=ODBC+Driver+17+for+SQL+Server"
        elif source_type == "PostgreSQL":
            conn_str = f"postgresql://{user}:{password}@{host}:{port}/{db_name}"
        elif source_type == "MySQL":
            conn_str = f"mysql+pymysql://{user}:{password}@{host}:{port}/{db_name}"
        else:
            raise ValueError("Unsupported source type")
        return create_engine(conn_str)
    except Exception as e:
        messagebox.showerror("Error", f"❌ Failed to connect to {source_type}: {e}")
        return None

def get_tables(source_type, engine):
    if source_type == "SQLite":
        query = "SELECT name FROM sqlite_master WHERE type='table';"
        return pd.read_sql(query, engine)['name'].tolist()
    elif source_type == "MySQL":
        return pd.read_sql("SHOW TABLES", engine).iloc[:, 0].tolist()
    elif source_type == "SQL Server":
        return pd.read_sql("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE='BASE TABLE'", engine)["TABLE_NAME"].tolist()
    else:  # PostgreSQL
        return pd.read_sql(text("SELECT table_name FROM information_schema.tables WHERE table_schema='public'"), engine)["table_name"].tolist()

def migrate_schema(source_type, source_details, dest_type, dest_details):
    try:
        if source_type in ["SQLite", "PostgreSQL", "MySQL", "SQL Server"]:
            engine = get_sql_engine(source_type, **source_details)
            if not engine:
                return
            tables = get_tables(source_type, engine)
            messagebox.showinfo("Schema Migration", f"✅ Extracted {len(tables)} tables from {source_type}.")
            if dest_type == "MongoDB":
                client = MongoClient(dest_details["uri"])
                db = client[dest_details["db_name"]]
                for table in tables:
                    if table not in db.list_collection_names():
                        db.create_collection(table)
                client.close()
                messagebox.showinfo("Schema Migration", "✅ Schema created in MongoDB.")
        else:
            messagebox.showerror("Error", "Schema migration only supported for SQL sources.")
    except Exception as e:
        messagebox.showerror("Error", f"❌ Schema migration failed: {e}")

def migrate_data(source_type, source_details, dest_type, dest_details, batch_size=None):
    try:
        engine = get_sql_engine(source_type, **source_details)
        if not engine:
            return
        tables = get_tables(source_type, engine)
        if dest_type == "MongoDB":
            client = MongoClient(dest_details["uri"])
            db = client[dest_details["db_name"]]
            for table in tables:
                df = pd.read_sql(f"SELECT * FROM {table}", engine)
                if df.empty:
                    continue
                if batch_size:
                    for i in range(0, len(df), batch_size):
                        batch = df.iloc[i:i + batch_size].to_dict('records')
                        db[table].insert_many(batch)
                else:
                    db[table].insert_many(df.to_dict('records'))
            client.close()
            messagebox.showinfo("Data Migration", "✅ Data migrated to MongoDB successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"❌ Data migration failed: {e}")

def perform_migration(technique, source_type, source_details, dest_type, dest_details):
    try:
        if technique == "Big Bang":
            migrate_schema(source_type, source_details, dest_type, dest_details)
            migrate_data(source_type, source_details, dest_type, dest_details)
            messagebox.showinfo("Big Bang", "✅ Complete migration done!")
        elif technique == "Layer by Layer (Phased)":
            migrate_schema(source_type, source_details, dest_type, dest_details)
            migrate_data(source_type, source_details, dest_type, dest_details, batch_size=100)
            messagebox.showinfo("Phased", "✅ Incremental migration done!")
        elif technique == "Parallel Run":
            temp_dest = dest_details.copy()
            temp_dest["db_name"] = temp_dest["db_name"] + "_temp"
            migrate_schema(source_type, source_details, dest_type, temp_dest)
            migrate_data(source_type, source_details, dest_type, temp_dest)
            if dest_type == "MongoDB":
                client = MongoClient(temp_dest["uri"])
                old_count = client[dest_details["db_name"]]["users"].count_documents({})
                new_count = client[temp_dest["db_name"]]["users"].count_documents({})
                messagebox.showinfo("Parallel", f"✅ Parallel run complete.\nOld: {old_count}, New: {new_count}")
                client.close()
        else:
            messagebox.showwarning("Warning", "Select a migration technique.")
    except Exception as e:
        messagebox.showerror("Error", f"❌ Migration failed: {e}")

# ------------------ APP UI ------------------
ctk.set_default_color_theme("blue")
ctk.set_appearance_mode("light")

app = ctk.CTk()
app.title("Secure Login System")
app.geometry("820x520")
app.resizable(False, False)

# ------------------ LEFT IMAGE PANEL ------------------
try:
    bg_image = ctk.CTkImage(
        light_image=Image.open("gemini.png"),
        dark_image=Image.open("gemini.png"),
        size=(400, 520)
    )
    left_label = ctk.CTkLabel(app, image=bg_image, text="")
    left_label.place(x=0, y=0)
except Exception:
    left_label = ctk.CTkFrame(app, width=400, height=520, fg_color="#5E17EB")
    left_label.place(x=0, y=0)

# ------------------ RIGHT PANEL ------------------
right_frame = ctk.CTkFrame(app, width=420, height=520, fg_color="white", corner_radius=0)
right_frame.place(x=820, y=0)

def slide_right_frame():
    current_x = right_frame.winfo_x()
    if current_x > 400:
        right_frame.place(x=current_x - 20, y=0)
        app.after(10, slide_right_frame)
    else:
        right_frame.place(x=400, y=0)
app.after(100, slide_right_frame)

# ------------------ TOGGLE THEME ------------------
def toggle_theme():
    current = ctk.get_appearance_mode()
    if current == "Light":
        ctk.set_appearance_mode("dark")
        theme_btn.configure(text="☀️ Light Mode")
    else:
        ctk.set_appearance_mode("light")
        theme_btn.configure(text="🌙 Dark Mode")

theme_btn = ctk.CTkButton(right_frame, text="🌙 Dark Mode", width=130, height=28,
                          command=toggle_theme, fg_color="#EDEDED", text_color="black",
                          hover_color="#D0D0D0", corner_radius=8)
theme_btn.place(x=260, y=20)

# ------------------ LOGIN UI ------------------
title = ctk.CTkLabel(right_frame, text="DB Migration Portal", text_color="#5E17EB", font=("Roboto", 28, "bold"))
title.place(x=80, y=50)

subtitle = ctk.CTkLabel(right_frame, text="Sign in to your account", text_color="gray", font=("Roboto", 14))
subtitle.place(x=125, y=90)

email_entry = ctk.CTkEntry(right_frame, placeholder_text="Email", width=240, height=35)
email_entry.place(x=90, y=180)

password_entry = ctk.CTkEntry(right_frame, placeholder_text="Password", show="*", width=240, height=35)
password_entry.place(x=90, y=230)

# ------------------ MIGRATION WINDOW ------------------
def open_migration_window():
    migration_win = ctk.CTkToplevel(app)
    migration_win.title("Advanced DB Migration Tool")
    migration_win.geometry("600x500")
    migration_win.resizable(True, True)

    # Restore login window when migration window closes
    migration_win.protocol("WM_DELETE_WINDOW", lambda: [app.deiconify(), migration_win.destroy()])

    mig_title = ctk.CTkLabel(migration_win, text="Database Migration: SQL → MongoDB", font=("Roboto", 22, "bold"))
    mig_title.pack(pady=10)
    scrollable_frame = ctk.CTkScrollableFrame(migration_win, width=580, height=420, fg_color="transparent")
    scrollable_frame.pack(fill="both", expand=True, padx=10, pady=10)
    # Source frame
    source_frame = ctk.CTkFrame(scrollable_frame)
    source_frame.pack(pady=10, padx=20, fill="x")
    ctk.CTkLabel(source_frame, text="Source (SQL):", font=("Roboto", 16, "bold")).pack(anchor="w", padx=10)
    source_type = ctk.CTkComboBox(source_frame, values=["SQLite", "PostgreSQL", "MySQL", "SQL Server"], width=200)
    source_type.pack(pady=5, padx=10)
    labels = ["Host", "Port", "Username", "Password", "Database Name / File Path"]
    entries = []
    for label in labels:
        ctk.CTkLabel(source_frame, text=f"{label}:").pack(anchor="w", padx=10)
        ent = ctk.CTkEntry(source_frame, width=200, placeholder_text=label.lower())
        if label == "Password":
            ent.configure(show="*")
        ent.pack(pady=2, padx=10)
        entries.append(ent)
    source_host, source_port, source_user, source_pass, source_db = entries
    # Destination frame
    dest_frame = ctk.CTkFrame(scrollable_frame)
    dest_frame.pack(pady=10, padx=20, fill="x")
    ctk.CTkLabel(dest_frame, text="Destination (MongoDB):", font=("Roboto", 16, "bold")).pack(anchor="w", padx=10)
    dest_uri = ctk.CTkEntry(dest_frame, width=500, placeholder_text="mongodb://localhost:27017/")
    dest_uri.pack(pady=2, padx=10)
    dest_mongo_db = ctk.CTkEntry(dest_frame, width=200, placeholder_text="DB Name")
    dest_mongo_db.pack(pady=2, padx=10)
    # Migration technique
    tech_frame = ctk.CTkFrame(scrollable_frame)
    tech_frame.pack(pady=10, padx=20, fill="x")
    ctk.CTkLabel(tech_frame, text="Migration Technique:", font=("Roboto", 16, "bold")).pack(anchor="w", padx=10)
    technique_combo = ctk.CTkComboBox(tech_frame, values=["Big Bang", "Layer by Layer (Phased)", "Parallel Run"], width=300)
    technique_combo.pack(pady=10, padx=10)

    def run_migration():
        try:
            s_details = {
                "host": source_host.get(),
                "port": int(source_port.get()) if source_port.get().isdigit() else None,
                "user": source_user.get(),
                "password": source_pass.get(),
                "db_name": source_db.get()
            }
            d_details = {"uri": dest_uri.get(), "db_name": dest_mongo_db.get()}
            selected_tech = technique_combo.get()
            if selected_tech:
                perform_migration(selected_tech, source_type.get(), s_details, "MongoDB", d_details)
            else:
                messagebox.showwarning("Warning", "Select a technique.")
        except ValueError as e:
            messagebox.showerror("Error", f"❌ Invalid input: {e}")

    mig_btn = ctk.CTkButton(scrollable_frame, text="Run Migration", command=run_migration, width=300, fg_color="#5E17EB")
    mig_btn.pack(pady=20)

    # Add logout button
    logout_btn = ctk.CTkButton(scrollable_frame, text="Logout", fg_color="#FF4C4C", command=lambda: [app.deiconify(), migration_win.destroy()])
    logout_btn.pack(pady=10)

# ------------------ DVC SETUP WINDOW ------------------
def open_dvc_setup_window():
    dvc_win = ctk.CTkToplevel(app)
    dvc_win.title("DVC Protection Setup")
    dvc_win.geometry("480x400")
    dvc_win.resizable(False, False)
 
    # Restore login window when DVC window closes
    dvc_win.protocol("WM_DELETE_WINDOW", lambda: [app.deiconify(), dvc_win.destroy()])

    ctk.CTkLabel(dvc_win, text="Configure DVC Protection", font=("Roboto", 22, "bold")).pack(pady=20)
    enable_switch = ctk.CTkSwitch(dvc_win, text="Enable DVC Protection", switch_width=60, switch_height=28)
    enable_switch.pack(pady=10)

    ctk.CTkLabel(dvc_win, text="DVC Type:", font=("Roboto", 14)).pack(pady=(20, 5))
    dvc_type = ctk.CTkComboBox(dvc_win, values=["Local", "Remote"], width=200)
    dvc_type.pack(pady=5)

    ctk.CTkLabel(dvc_win, text="Remote Path (Optional):", font=("Roboto", 14)).pack(pady=(20, 5))
    remote_entry = ctk.CTkEntry(dvc_win, placeholder_text="e.g., s3://bucket/data or C:/local_dvc_store", width=320)
    remote_entry.pack(pady=5)

    def save_and_continue():
        user_dvc_config["enabled"] = bool(enable_switch.get())
        user_dvc_config["type"] = dvc_type.get()
        user_dvc_config["remote_path"] = remote_entry.get().strip()
        dvc_win.destroy()
        open_migration_window()

    ctk.CTkButton(dvc_win, text="Continue", fg_color="#5E17EB", command=save_and_continue, width=200).pack(pady=30)

# ------------------ LOGIN / REGISTER ------------------
def login():
    email = email_entry.get()
    password = password_entry.get()
    if verify_user(email, password):
        messagebox.showinfo("Login", f"✅ Welcome, {email}!")
        app.withdraw()  # Hide the login window
        open_dvc_setup_window()
    else:
        messagebox.showerror("Error", "❌ Invalid email or password.")

def register():
    email = email_entry.get()
    password = password_entry.get()
    if email and password:
        register_user(email, password)
    else:
        messagebox.showwarning("Warning", "Please fill all fields.")

login_btn = ctk.CTkButton(right_frame, text="Login", fg_color="#5E17EB", hover_color="#7C3AED",
                          width=240, height=40, command=login)
login_btn.place(x=90, y=300)

register_btn = ctk.CTkButton(right_frame, text="Register", fg_color="#E0E0E0", text_color="black",
                             hover_color="#CFCFCF", width=240, height=40, command=register)
register_btn.place(x=90, y=360)

def on_enter(e, btn):
    btn.configure(width=250, height=44)
def on_leave(e, btn):
    btn.configure(width=240, height=40)

login_btn.bind("<Enter>", lambda e: on_enter(e, login_btn))
login_btn.bind("<Leave>", lambda e: on_leave(e, login_btn))
register_btn.bind("<Enter>", lambda e: on_enter(e, register_btn))
register_btn.bind("<Leave>", lambda e: on_leave(e, register_btn))

app.mainloop()