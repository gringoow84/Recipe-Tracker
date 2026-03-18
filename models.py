"""
Database models for Recipe Tracker.
Uses PostgreSQL when DATABASE_URL env var is set, otherwise SQLite.
All tables are prefixed with rt_ to avoid conflicts with shared databases.
"""

import os
import json
from datetime import datetime
from crypto import encrypt, decrypt

DATABASE_URL = os.environ.get("DATABASE_URL")


def _get_conn():
    if DATABASE_URL:
        import psycopg2
        import psycopg2.extras
        conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
        return conn
    else:
        import sqlite3
        db_path = os.path.join(os.path.dirname(__file__), "recipe_tracker.db")
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        return conn


def _p():
    return "%s" if DATABASE_URL else "?"


def _cursor(conn):
    return conn.cursor()


def _lastrowid(conn, cursor):
    if DATABASE_URL:
        cursor.execute("SELECT lastval()")
        return cursor.fetchone()["lastval"]
    return cursor.lastrowid


def init_db():
    conn = _get_conn()
    c = _cursor(conn)

    if DATABASE_URL:
        c.execute("""
            CREATE TABLE IF NOT EXISTS rt_users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS rt_password_resets (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                expires_at TEXT NOT NULL
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS rt_recipes (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                category TEXT NOT NULL,
                description TEXT,
                prep_time INTEGER DEFAULT 0,
                cook_time INTEGER DEFAULT 0,
                servings INTEGER DEFAULT 4,
                calories_per_serving INTEGER DEFAULT 0,
                ingredients TEXT NOT NULL,
                instructions TEXT NOT NULL,
                notes TEXT,
                photo TEXT DEFAULT '',
                created_at TEXT NOT NULL
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS rt_meal_plans (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                plan_date TEXT NOT NULL,
                meal_type TEXT NOT NULL,
                recipe_id INTEGER NOT NULL
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS rt_shopping_items (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                ingredient TEXT NOT NULL,
                amount TEXT NOT NULL,
                unit TEXT NOT NULL,
                checked INTEGER DEFAULT 0,
                created_at TEXT NOT NULL
            )
        """)
    else:
        c.execute("""
            CREATE TABLE IF NOT EXISTS rt_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS rt_password_resets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                expires_at TEXT NOT NULL
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS rt_recipes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                category TEXT NOT NULL,
                description TEXT,
                prep_time INTEGER DEFAULT 0,
                cook_time INTEGER DEFAULT 0,
                servings INTEGER DEFAULT 4,
                calories_per_serving INTEGER DEFAULT 0,
                ingredients TEXT NOT NULL,
                instructions TEXT NOT NULL,
                notes TEXT,
                photo TEXT DEFAULT '',
                created_at TEXT NOT NULL
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS rt_meal_plans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                plan_date TEXT NOT NULL,
                meal_type TEXT NOT NULL,
                recipe_id INTEGER NOT NULL
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS rt_shopping_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                ingredient TEXT NOT NULL,
                amount TEXT NOT NULL,
                unit TEXT NOT NULL,
                checked INTEGER DEFAULT 0,
                created_at TEXT NOT NULL
            )
        """)

    conn.commit()
    conn.close()


def migrate_db():
    """Add new columns to existing tables without losing data."""
    conn = _get_conn()
    c = _cursor(conn)
    try:
        if DATABASE_URL:
            c.execute("ALTER TABLE rt_recipes ADD COLUMN IF NOT EXISTS photo TEXT DEFAULT ''")
        else:
            c.execute("PRAGMA table_info(rt_recipes)")
            cols = [row[1] for row in c.fetchall()]
            if "photo" not in cols:
                c.execute("ALTER TABLE rt_recipes ADD COLUMN photo TEXT DEFAULT ''")
        conn.commit()
    except Exception:
        conn.rollback()
    conn.close()


# ── Users ─────────────────────────────────────────────────────────────────────

def create_user(username, email, password_hash):
    conn = _get_conn()
    c = _cursor(conn)
    p = _p()
    c.execute(
        f"INSERT INTO rt_users (username,email,password_hash,created_at) VALUES ({p},{p},{p},{p})",
        (username, email, password_hash, datetime.utcnow().isoformat())
    )
    user_id = _lastrowid(conn, c)
    conn.commit()
    conn.close()
    return user_id


def get_user_by_username(username):
    conn = _get_conn()
    c = _cursor(conn)
    p = _p()
    c.execute(f"SELECT * FROM rt_users WHERE username = {p}", (username,))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_by_email(email):
    conn = _get_conn()
    c = _cursor(conn)
    p = _p()
    c.execute(f"SELECT * FROM rt_users WHERE email = {p}", (email,))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_by_id(user_id):
    conn = _get_conn()
    c = _cursor(conn)
    p = _p()
    c.execute(f"SELECT * FROM rt_users WHERE id = {p}", (user_id,))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None


def update_user_password(user_id, new_hash):
    conn = _get_conn()
    c = _cursor(conn)
    p = _p()
    c.execute(f"UPDATE rt_users SET password_hash = {p} WHERE id = {p}", (new_hash, user_id))
    conn.commit()
    conn.close()


# ── Password Resets ───────────────────────────────────────────────────────────

def create_reset_token(user_id, token, expires_at):
    conn = _get_conn()
    c = _cursor(conn)
    p = _p()
    c.execute(f"DELETE FROM rt_password_resets WHERE user_id = {p}", (user_id,))
    c.execute(
        f"INSERT INTO rt_password_resets (user_id,token,expires_at) VALUES ({p},{p},{p})",
        (user_id, token, expires_at)
    )
    conn.commit()
    conn.close()


def get_reset_token(token):
    conn = _get_conn()
    c = _cursor(conn)
    p = _p()
    c.execute(f"SELECT * FROM rt_password_resets WHERE token = {p}", (token,))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None


def delete_reset_token(token):
    conn = _get_conn()
    c = _cursor(conn)
    p = _p()
    c.execute(f"DELETE FROM rt_password_resets WHERE token = {p}", (token,))
    conn.commit()
    conn.close()


# ── Recipes ───────────────────────────────────────────────────────────────────

def _decrypt_recipe(row):
    row = dict(row)
    return {
        "id":                   row["id"],
        "user_id":              row["user_id"],
        "title":                decrypt(row["title"]),
        "category":             row["category"],
        "description":          decrypt(row["description"]) if row["description"] else "",
        "prep_time":            row["prep_time"],
        "cook_time":            row["cook_time"],
        "servings":             row["servings"],
        "calories_per_serving": row["calories_per_serving"],
        "ingredients":          json.loads(decrypt(row["ingredients"])) if row["ingredients"] else [],
        "instructions":         json.loads(decrypt(row["instructions"])) if row["instructions"] else [],
        "notes":                decrypt(row["notes"]) if row["notes"] else "",
        "photo":                row.get("photo") or "",
        "created_at":           row["created_at"],
    }


def get_all_recipes(user_id, category=None, search=None):
    conn = _get_conn()
    c = _cursor(conn)
    p = _p()
    c.execute(f"SELECT * FROM rt_recipes WHERE user_id = {p} ORDER BY created_at DESC", (user_id,))
    rows = c.fetchall()
    conn.close()
    recipes = [_decrypt_recipe(row) for row in rows]

    if category and category != "All":
        recipes = [r for r in recipes if r["category"] == category]

    if search:
        search_lower = search.lower()
        recipes = [r for r in recipes if
                   search_lower in r["title"].lower() or
                   search_lower in r["description"].lower() or
                   any(search_lower in ing["name"].lower() for ing in r["ingredients"])]
    return recipes


def get_recipe(recipe_id, user_id):
    conn = _get_conn()
    c = _cursor(conn)
    p = _p()
    c.execute(f"SELECT * FROM rt_recipes WHERE id = {p} AND user_id = {p}", (recipe_id, user_id))
    row = c.fetchone()
    conn.close()
    return _decrypt_recipe(row) if row else None


def add_recipe(user_id, title, category, description, prep_time, cook_time, servings, calories_per_serving, ingredients, instructions, notes, photo=""):
    conn = _get_conn()
    c = _cursor(conn)
    p = _p()
    c.execute(
        f"INSERT INTO rt_recipes (user_id,title,category,description,prep_time,cook_time,servings,calories_per_serving,ingredients,instructions,notes,photo,created_at) VALUES ({p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p})",
        (user_id, encrypt(title), category, encrypt(description),
         prep_time, cook_time, servings, calories_per_serving,
         encrypt(json.dumps(ingredients)), encrypt(json.dumps(instructions)),
         encrypt(notes), photo, datetime.utcnow().isoformat())
    )
    recipe_id = _lastrowid(conn, c)
    conn.commit()
    conn.close()
    return recipe_id


def update_recipe(recipe_id, user_id, title, category, description, prep_time, cook_time, servings, calories_per_serving, ingredients, instructions, notes, photo=None):
    conn = _get_conn()
    c = _cursor(conn)
    p = _p()
    if photo is not None:
        c.execute(
            f"UPDATE rt_recipes SET title={p},category={p},description={p},prep_time={p},cook_time={p},servings={p},calories_per_serving={p},ingredients={p},instructions={p},notes={p},photo={p} WHERE id={p} AND user_id={p}",
            (encrypt(title), category, encrypt(description),
             prep_time, cook_time, servings, calories_per_serving,
             encrypt(json.dumps(ingredients)), encrypt(json.dumps(instructions)),
             encrypt(notes), photo, recipe_id, user_id)
        )
    else:
        c.execute(
            f"UPDATE rt_recipes SET title={p},category={p},description={p},prep_time={p},cook_time={p},servings={p},calories_per_serving={p},ingredients={p},instructions={p},notes={p} WHERE id={p} AND user_id={p}",
            (encrypt(title), category, encrypt(description),
             prep_time, cook_time, servings, calories_per_serving,
             encrypt(json.dumps(ingredients)), encrypt(json.dumps(instructions)),
             encrypt(notes), recipe_id, user_id)
        )
    conn.commit()
    conn.close()


def delete_recipe(recipe_id, user_id):
    conn = _get_conn()
    c = _cursor(conn)
    p = _p()
    c.execute(f"DELETE FROM rt_meal_plans WHERE recipe_id = {p} AND user_id = {p}", (recipe_id, user_id))
    c.execute(f"DELETE FROM rt_recipes WHERE id = {p} AND user_id = {p}", (recipe_id, user_id))
    conn.commit()
    conn.close()


# ── Meal Plans ────────────────────────────────────────────────────────────────

def get_meal_plan_week(user_id, week_start, week_end):
    conn = _get_conn()
    c = _cursor(conn)
    p = _p()
    c.execute(
        f"""SELECT mp.*, r.title AS recipe_title_enc, r.calories_per_serving
            FROM rt_meal_plans mp
            JOIN rt_recipes r ON mp.recipe_id = r.id
            WHERE mp.user_id = {p} AND mp.plan_date >= {p} AND mp.plan_date <= {p}
            ORDER BY mp.plan_date, mp.meal_type""",
        (user_id, week_start, week_end)
    )
    rows = c.fetchall()
    conn.close()
    result = []
    for row in rows:
        r = dict(row)
        r["recipe_title"] = decrypt(r["recipe_title_enc"])
        result.append(r)
    return result


def add_to_meal_plan(user_id, plan_date, meal_type, recipe_id):
    conn = _get_conn()
    c = _cursor(conn)
    p = _p()
    c.execute(
        f"INSERT INTO rt_meal_plans (user_id,plan_date,meal_type,recipe_id) VALUES ({p},{p},{p},{p})",
        (user_id, plan_date, meal_type, recipe_id)
    )
    conn.commit()
    conn.close()


def remove_from_meal_plan(plan_id, user_id):
    conn = _get_conn()
    c = _cursor(conn)
    p = _p()
    c.execute(f"DELETE FROM rt_meal_plans WHERE id = {p} AND user_id = {p}", (plan_id, user_id))
    conn.commit()
    conn.close()


def get_meal_plan_recipes(user_id, date_from, date_to):
    """Get all recipe ingredients for a date range (for shopping list)."""
    conn = _get_conn()
    c = _cursor(conn)
    p = _p()
    c.execute(
        f"""SELECT DISTINCT r.ingredients
            FROM rt_meal_plans mp
            JOIN rt_recipes r ON mp.recipe_id = r.id
            WHERE mp.user_id = {p} AND mp.plan_date >= {p} AND mp.plan_date <= {p}""",
        (user_id, date_from, date_to)
    )
    rows = c.fetchall()
    conn.close()
    all_ingredients = []
    for row in rows:
        r = dict(row)
        ingredients = json.loads(decrypt(r["ingredients"]))
        all_ingredients.extend(ingredients)
    return all_ingredients


# ── Shopping List ─────────────────────────────────────────────────────────────

def get_shopping_list(user_id):
    conn = _get_conn()
    c = _cursor(conn)
    p = _p()
    c.execute(f"SELECT * FROM rt_shopping_items WHERE user_id = {p} ORDER BY checked, created_at DESC", (user_id,))
    rows = c.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def add_shopping_item(user_id, ingredient, amount, unit):
    conn = _get_conn()
    c = _cursor(conn)
    p = _p()
    c.execute(
        f"INSERT INTO rt_shopping_items (user_id,ingredient,amount,unit,checked,created_at) VALUES ({p},{p},{p},{p},0,{p})",
        (user_id, ingredient, amount, unit, datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()


def toggle_shopping_item(item_id, user_id):
    conn = _get_conn()
    c = _cursor(conn)
    p = _p()
    c.execute(f"UPDATE rt_shopping_items SET checked = 1 - checked WHERE id = {p} AND user_id = {p}", (item_id, user_id))
    conn.commit()
    conn.close()


def clear_shopping_list(user_id, checked_only=False):
    conn = _get_conn()
    c = _cursor(conn)
    p = _p()
    if checked_only:
        c.execute(f"DELETE FROM rt_shopping_items WHERE user_id = {p} AND checked = 1", (user_id,))
    else:
        c.execute(f"DELETE FROM rt_shopping_items WHERE user_id = {p}", (user_id,))
    conn.commit()
    conn.close()
