"""
Recipe Tracker Flask Web Application
"""

import os
import secrets
import json
import base64
from datetime import datetime, timedelta, date
from functools import wraps

import bcrypt
from flask import (
    Flask, render_template, redirect, url_for, session,
    request, flash, Response, stream_with_context, jsonify
)

import models
from helpers import CATEGORIES, CATEGORY_ICONS, CATEGORY_COLORS, scale_ingredients

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

SECRET_KEY_FILE = os.path.join(os.path.dirname(__file__), "flask_secret.key")


def _load_flask_secret():
    env_key = os.environ.get("FLASK_SECRET_KEY")
    if env_key:
        return env_key
    if os.path.exists(SECRET_KEY_FILE):
        with open(SECRET_KEY_FILE, "r") as f:
            return f.read().strip()
    key = secrets.token_hex(32)
    with open(SECRET_KEY_FILE, "w") as f:
        f.write(key)
    return key


app = Flask(__name__)
app.secret_key = _load_flask_secret()

models.init_db()
models.migrate_db()

# ---------------------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------------------


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Email helper
# ---------------------------------------------------------------------------


def send_reset_email(to_email, reset_link):
    import resend
    api_key = os.environ.get("RESEND_API_KEY", "")
    if not api_key:
        raise ValueError("RESEND_API_KEY is not set.")
    resend.api_key = api_key
    from_addr = os.environ.get("RESEND_FROM", "Recipe Tracker <onboarding@resend.dev>")
    resend.Emails.send({
        "from": from_addr,
        "to": [to_email],
        "subject": "Recipe Tracker — Password Reset",
        "text": f"""Hello,

You requested a password reset for your Recipe Tracker account.

Click the link below to reset your password (expires in 1 hour):

{reset_link}

If you did not request this, ignore this email.

— Recipe Tracker
"""
    })


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------


@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = models.get_user_by_username(username)
        if not user or not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
            flash("Invalid username or password.", "danger")
            return render_template("login.html")
        session.clear()
        session["user_id"] = user["id"]
        flash(f"Welcome back, {user['username']}!", "success")
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not username or not email or not password:
            flash("All fields are required.", "danger")
            return render_template("register.html")
        if len(username) < 3:
            flash("Username must be at least 3 characters.", "danger")
            return render_template("register.html")
        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("register.html")
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return render_template("register.html")
        if models.get_user_by_username(username):
            flash("Username already taken.", "danger")
            return render_template("register.html")

        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        try:
            models.create_user(username, email, password_hash)
        except Exception:
            flash("Registration failed. Email may already be in use.", "danger")
            return render_template("register.html")

        flash("Account created! Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        user = models.get_user_by_email(email)
        if user:
            token = secrets.token_urlsafe(32)
            expires_at = (datetime.utcnow() + timedelta(hours=1)).isoformat()
            models.create_reset_token(user["id"], token, expires_at)
            app_url = os.environ.get("APP_URL", request.host_url.rstrip("/"))
            reset_link = f"{app_url}/reset-password/{token}"
            try:
                send_reset_email(email, reset_link)
            except Exception as e:
                print(f"[email error] {e}")
                flash("Could not send reset email. Please contact support.", "danger")
                return render_template("forgot_password.html")
        flash("If that email is registered, a reset link has been sent.", "info")
        return redirect(url_for("login"))
    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    record = models.get_reset_token(token)
    if not record:
        flash("Invalid or expired reset link.", "danger")
        return redirect(url_for("login"))
    expires_at = datetime.fromisoformat(record["expires_at"])
    if datetime.utcnow() > expires_at:
        models.delete_reset_token(token)
        flash("Reset link expired. Please request a new one.", "danger")
        return redirect(url_for("forgot_password"))
    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return render_template("reset_password.html", token=token)
        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("reset_password.html", token=token)
        new_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        models.update_user_password(record["user_id"], new_hash)
        models.delete_reset_token(token)
        flash("Password reset successfully! Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("reset_password.html", token=token)


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------


@app.route("/dashboard")
@login_required
def dashboard():
    user_id = session["user_id"]
    category = request.args.get("category", "All")
    search = request.args.get("search", "").strip()
    recipes = models.get_all_recipes(user_id, category=category, search=search)
    return render_template(
        "dashboard.html",
        recipes=recipes,
        categories=CATEGORIES,
        category_icons=CATEGORY_ICONS,
        category_colors=CATEGORY_COLORS,
        active_category=category,
        search=search,
    )


# ---------------------------------------------------------------------------
# Recipe CRUD
# ---------------------------------------------------------------------------


@app.route("/recipes/<int:recipe_id>")
@login_required
def recipe_detail(recipe_id):
    user_id = session["user_id"]
    recipe = models.get_recipe(recipe_id, user_id)
    if not recipe:
        flash("Recipe not found.", "danger")
        return redirect(url_for("dashboard"))
    servings = int(request.args.get("servings", recipe["servings"]))
    scaled_ingredients = scale_ingredients(recipe["ingredients"], recipe["servings"], servings)
    return render_template(
        "recipe_detail.html",
        recipe=recipe,
        scaled_ingredients=scaled_ingredients,
        servings=servings,
        category_colors=CATEGORY_COLORS,
        category_icons=CATEGORY_ICONS,
    )


@app.route("/recipes/add", methods=["GET", "POST"])
@login_required
def add_recipe():
    if request.method == "POST":
        user_id = session["user_id"]
        try:
            title = request.form["title"].strip()
            category = request.form["category"]
            description = request.form.get("description", "").strip()
            prep_time = int(request.form.get("prep_time", 0) or 0)
            cook_time = int(request.form.get("cook_time", 0) or 0)
            servings = int(request.form.get("servings", 4) or 4)
            calories = int(request.form.get("calories_per_serving", 0) or 0)
            notes = request.form.get("notes", "").strip()

            # Parse ingredients
            ing_names = request.form.getlist("ing_name[]")
            ing_amounts = request.form.getlist("ing_amount[]")
            ing_units = request.form.getlist("ing_unit[]")
            ingredients = [
                {"name": n.strip(), "amount": a.strip(), "unit": u.strip()}
                for n, a, u in zip(ing_names, ing_amounts, ing_units) if n.strip()
            ]

            # Parse instructions
            instructions = [s.strip() for s in request.form.getlist("step[]") if s.strip()]

            # Photo (base64 string sent from client-side canvas compression)
            photo = request.form.get("photo_data", "").strip()

            if not title:
                raise ValueError("Title is required.")
            if not ingredients:
                raise ValueError("At least one ingredient is required.")
            if not instructions:
                raise ValueError("At least one instruction step is required.")

            recipe_id = models.add_recipe(
                user_id, title, category, description,
                prep_time, cook_time, servings, calories,
                ingredients, instructions, notes, photo
            )
            flash(f"Recipe '{title}' added successfully!", "success")
            return redirect(url_for("recipe_detail", recipe_id=recipe_id))
        except Exception as e:
            print(f"[add_recipe error] {e}")
            flash(f"Error adding recipe: {e}", "danger")

    return render_template("recipe_form.html", mode="add", recipe=None, categories=CATEGORIES)


@app.route("/recipes/<int:recipe_id>/edit", methods=["GET", "POST"])
@login_required
def edit_recipe(recipe_id):
    user_id = session["user_id"]
    recipe = models.get_recipe(recipe_id, user_id)
    if not recipe:
        flash("Recipe not found.", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        try:
            title = request.form["title"].strip()
            category = request.form["category"]
            description = request.form.get("description", "").strip()
            prep_time = int(request.form.get("prep_time", 0) or 0)
            cook_time = int(request.form.get("cook_time", 0) or 0)
            servings = int(request.form.get("servings", 4) or 4)
            calories = int(request.form.get("calories_per_serving", 0) or 0)
            notes = request.form.get("notes", "").strip()

            ing_names = request.form.getlist("ing_name[]")
            ing_amounts = request.form.getlist("ing_amount[]")
            ing_units = request.form.getlist("ing_unit[]")
            ingredients = [
                {"name": n.strip(), "amount": a.strip(), "unit": u.strip()}
                for n, a, u in zip(ing_names, ing_amounts, ing_units) if n.strip()
            ]

            instructions = [s.strip() for s in request.form.getlist("step[]") if s.strip()]

            # Photo — only update if a new one was uploaded, otherwise keep existing
            photo_data = request.form.get("photo_data", "").strip()
            photo = photo_data if photo_data else None

            if not title:
                raise ValueError("Title is required.")

            models.update_recipe(
                recipe_id, user_id, title, category, description,
                prep_time, cook_time, servings, calories,
                ingredients, instructions, notes, photo
            )
            flash(f"Recipe '{title}' updated!", "success")
            return redirect(url_for("recipe_detail", recipe_id=recipe_id))
        except Exception as e:
            print(f"[edit_recipe error] {e}")
            flash(f"Error updating recipe: {e}", "danger")

    return render_template("recipe_form.html", mode="edit", recipe=recipe, categories=CATEGORIES)


@app.route("/recipes/<int:recipe_id>/delete", methods=["POST"])
@login_required
def delete_recipe(recipe_id):
    user_id = session["user_id"]
    recipe = models.get_recipe(recipe_id, user_id)
    if recipe:
        models.delete_recipe(recipe_id, user_id)
        flash(f"Recipe '{recipe['title']}' deleted.", "success")
    return redirect(url_for("dashboard"))


# ---------------------------------------------------------------------------
# AI Import — parse recipe from text or image
# ---------------------------------------------------------------------------


@app.route("/ai/import", methods=["POST"])
@login_required
def ai_import():
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        return jsonify({"error": "GROQ_API_KEY is not set."}), 500

    from groq import Groq
    client = Groq(api_key=api_key)

    import_type = request.form.get("import_type", "text")
    prompt_prefix = (
        "You are a recipe parser. Extract the recipe and return ONLY valid JSON with this exact structure:\n"
        '{"title":"","category":"one of: Breakfast,Lunch,Dinner,Pasta,Chinese,Healthy,Mexican,Italian,Seafood,Soup,Salad,Dessert,Vegetarian,Vegan,Quick & Easy,Other",'
        '"description":"","prep_time":0,"cook_time":0,"servings":4,"calories_per_serving":0,'
        '"ingredients":[{"amount":"","unit":"","name":""}],'
        '"instructions":["step 1","step 2"],"notes":""}\n'
        "Return ONLY the JSON, no markdown, no explanation.\n\n"
    )

    try:
        if import_type == "image":
            file = request.files.get("image")
            if not file:
                return jsonify({"error": "No image uploaded."}), 400
            img_bytes = file.read()
            img_b64 = base64.standard_b64encode(img_bytes).decode("utf-8")
            ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else "jpeg"
            mime = f"image/{ext}" if ext in ("jpg", "jpeg", "png", "gif", "webp") else "image/jpeg"

            response = client.chat.completions.create(
                model="meta-llama/llama-4-scout-17b-16e-instruct",
                messages=[{
                    "role": "user",
                    "content": [
                        {"type": "text", "text": prompt_prefix + "Extract the recipe from this image."},
                        {"type": "image_url", "image_url": {"url": f"data:{mime};base64,{img_b64}"}}
                    ]
                }],
                max_tokens=2000,
            )
        elif import_type == "search":
            query = request.form.get("text", "").strip()
            if not query:
                return jsonify({"error": "No recipe name provided."}), 400

            response = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[{
                    "role": "user",
                    "content": prompt_prefix + f"Generate a complete, authentic recipe for: {query}"
                }],
                max_tokens=2000,
            )

        else:
            text = request.form.get("text", "").strip()
            if not text:
                return jsonify({"error": "No text provided."}), 400

            # If it looks like a URL, fetch the page
            if text.startswith("http://") or text.startswith("https://"):
                try:
                    import urllib.request
                    req = urllib.request.Request(text, headers={"User-Agent": "Mozilla/5.0"})
                    with urllib.request.urlopen(req, timeout=10) as resp:
                        html = resp.read().decode("utf-8", errors="ignore")
                    # Strip HTML tags simply
                    import re
                    clean = re.sub(r"<[^>]+>", " ", html)
                    clean = re.sub(r"\s+", " ", clean)[:4000]
                    text = clean
                except Exception:
                    pass

            response = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[{
                    "role": "user",
                    "content": prompt_prefix + text
                }],
                max_tokens=2000,
            )

        raw = response.choices[0].message.content.strip()
        # Strip markdown code blocks if present
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        data = json.loads(raw)
        return jsonify(data)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# Meal Planner
# ---------------------------------------------------------------------------


@app.route("/meal-planner")
@login_required
def meal_planner():
    user_id = session["user_id"]

    # Get week offset from query param
    week_offset = int(request.args.get("week", 0))
    today = date.today()
    monday = today - timedelta(days=today.weekday()) + timedelta(weeks=week_offset)
    sunday = monday + timedelta(days=6)

    week_dates = [monday + timedelta(days=i) for i in range(7)]
    meal_types = ["Breakfast", "Lunch", "Dinner"]

    plans = models.get_meal_plan_week(user_id, monday.isoformat(), sunday.isoformat())

    # Build a lookup: {date: {meal_type: [plan_entries]}}
    plan_map = {}
    for p in plans:
        d = p["plan_date"]
        m = p["meal_type"]
        if d not in plan_map:
            plan_map[d] = {}
        if m not in plan_map[d]:
            plan_map[d][m] = []
        plan_map[d][m].append(p)

    # Total calories per day
    day_calories = {}
    for p in plans:
        d = p["plan_date"]
        day_calories[d] = day_calories.get(d, 0) + p["calories_per_serving"]

    all_recipes = models.get_all_recipes(user_id)

    return render_template(
        "meal_planner.html",
        week_dates=week_dates,
        meal_types=meal_types,
        plan_map=plan_map,
        day_calories=day_calories,
        week_offset=week_offset,
        all_recipes=all_recipes,
        monday=monday,
        sunday=sunday,
        today_str=date.today().isoformat(),
    )


@app.route("/meal-planner/add", methods=["POST"])
@login_required
def add_to_meal_plan():
    user_id = session["user_id"]
    plan_date = request.form.get("plan_date")
    meal_type = request.form.get("meal_type")
    recipe_id = request.form.get("recipe_id")
    week_offset = request.form.get("week_offset", 0)

    if plan_date and meal_type and recipe_id:
        recipe = models.get_recipe(int(recipe_id), user_id)
        if recipe:
            models.add_to_meal_plan(user_id, plan_date, meal_type, int(recipe_id))
            flash(f"'{recipe['title']}' added to {meal_type} on {plan_date}.", "success")

    return redirect(url_for("meal_planner", week=week_offset))


@app.route("/meal-planner/remove/<int:plan_id>", methods=["POST"])
@login_required
def remove_from_meal_plan(plan_id):
    user_id = session["user_id"]
    week_offset = request.form.get("week_offset", 0)
    models.remove_from_meal_plan(plan_id, user_id)
    return redirect(url_for("meal_planner", week=week_offset))


# ---------------------------------------------------------------------------
# Shopping List
# ---------------------------------------------------------------------------


@app.route("/shopping-list")
@login_required
def shopping_list():
    user_id = session["user_id"]
    items = models.get_shopping_list(user_id)
    return render_template("shopping_list.html", items=items)


@app.route("/shopping-list/generate", methods=["POST"])
@login_required
def generate_shopping_list():
    user_id = session["user_id"]
    date_from = request.form.get("date_from")
    date_to = request.form.get("date_to")

    if not date_from or not date_to:
        flash("Please select a date range.", "warning")
        return redirect(url_for("shopping_list"))

    ingredients = models.get_meal_plan_recipes(user_id, date_from, date_to)
    if not ingredients:
        flash("No meals planned for that date range.", "warning")
        return redirect(url_for("shopping_list"))

    for ing in ingredients:
        models.add_shopping_item(user_id, ing["name"], ing["amount"], ing["unit"])

    flash(f"Added {len(ingredients)} ingredients to your shopping list.", "success")
    return redirect(url_for("shopping_list"))


@app.route("/recipes/<int:recipe_id>/add-to-shopping", methods=["POST"])
@login_required
def add_to_shopping_from_recipe(recipe_id):
    user_id = session["user_id"]
    recipe = models.get_recipe(recipe_id, user_id)
    if recipe:
        for ing in recipe["ingredients"]:
            models.add_shopping_item(user_id, ing["name"], ing["amount"], ing["unit"])
        flash(f"Added {len(recipe['ingredients'])} ingredients from '{recipe['title']}' to shopping list.", "success")
    return redirect(url_for("shopping_list"))


@app.route("/shopping-list/add", methods=["POST"])
@login_required
def add_shopping_item():
    user_id = session["user_id"]
    ingredient = request.form.get("ingredient", "").strip()
    amount = request.form.get("amount", "").strip()
    unit = request.form.get("unit", "").strip()
    if ingredient:
        models.add_shopping_item(user_id, ingredient, amount, unit)
    return redirect(url_for("shopping_list"))


@app.route("/shopping-list/toggle/<int:item_id>", methods=["POST"])
@login_required
def toggle_shopping_item(item_id):
    models.toggle_shopping_item(item_id, session["user_id"])
    return redirect(url_for("shopping_list"))


@app.route("/shopping-list/clear", methods=["POST"])
@login_required
def clear_shopping_list():
    user_id = session["user_id"]
    checked_only = request.form.get("checked_only") == "1"
    models.clear_shopping_list(user_id, checked_only=checked_only)
    flash("Shopping list cleared.", "info")
    return redirect(url_for("shopping_list"))


# ---------------------------------------------------------------------------
# AI Recipe Suggester
# ---------------------------------------------------------------------------


@app.route("/ai")
@login_required
def ai():
    has_api_key = bool(os.environ.get("GROQ_API_KEY"))
    return render_template("ai_suggest.html", has_api_key=has_api_key)


@app.route("/ai/chat", methods=["POST"])
@login_required
def ai_chat():
    if not os.environ.get("GROQ_API_KEY"):
        def error_stream():
            yield 'data: {"error": "GROQ_API_KEY is not configured."}\n\n'
        return Response(stream_with_context(error_stream()), mimetype="text/event-stream")

    data = request.get_json(silent=True) or {}
    question = data.get("question", "").strip()
    history = data.get("history", [])

    if not question:
        def error_stream():
            yield 'data: {"error": "No question provided."}\n\n'
        return Response(stream_with_context(error_stream()), mimetype="text/event-stream")

    user_id = session["user_id"]
    recipes = models.get_all_recipes(user_id)
    recipe_list = "\n".join([f"- {r['title']} ({r['category']}, {r['calories_per_serving']} cal)" for r in recipes[:20]]) or "No recipes saved yet."

    system_prompt = (
        "You are a friendly, creative personal chef and recipe advisor. "
        "Help users find recipes, suggest meal ideas, answer cooking questions, "
        "and provide tips on nutrition, substitutions, and cooking techniques. "
        "Be enthusiastic and encouraging.\n\n"
        f"The user's saved recipes:\n{recipe_list}\n\n"
        f"Today's date: {date.today().isoformat()}"
    )

    def generate():
        try:
            from groq import Groq
            client = Groq(api_key=os.environ["GROQ_API_KEY"])

            messages = [{"role": "system", "content": system_prompt}]
            for h in history:
                role = h.get("role", "user")
                content = h.get("content", "")
                if role in ("user", "assistant") and content:
                    messages.append({"role": role, "content": content})
            messages.append({"role": "user", "content": question})

            stream = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=messages,
                stream=True,
            )
            for chunk in stream:
                token = chunk.choices[0].delta.content
                if token:
                    yield f"data: {json.dumps({'token': token})}\n\n"
            yield 'data: {"done": true}\n\n'

        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

    return Response(stream_with_context(generate()), mimetype="text/event-stream")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port)
