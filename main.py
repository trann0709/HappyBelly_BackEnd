import json
import os
import requests
from dotenv import load_dotenv
import psycopg2
import psycopg2.extras
from flask import Flask, request, jsonify
from datetime import datetime, timedelta, timezone
from flask_jwt_extended import (
    create_access_token,
    get_jwt_identity,
    get_jwt,
    jwt_required,
    JWTManager,
    set_access_cookies,
    unset_jwt_cookies,
)
from werkzeug.security import check_password_hash, generate_password_hash
import math
from flask_cors import CORS

load_dotenv(dotenv_path="./.env.local")

DEBUG = bool(os.environ.get("DEBUG", True))
app = Flask(__name__)
CORS(app, supports_credentials=True)
app.config["DEBUG"] = DEBUG
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY")
app.config["JWT_COOKIE_SECURE"] = False
app.config["JWT_TOKEN_LOCATION"] = ["headers", "cookies"]
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=8)
jwt = JWTManager(app)


URL = "https://www.themealdb.com/api/json/v1/1/"
RECIPES_PER_PAGE = 6


@app.after_request
def refresh_expiring_jwts(response):
    try:
        exp_timestamp = get_jwt()["exp"]
        now = datetime.now(timezone.utc)
        target_timestamp = datetime.timestamp(now + timedelta(hours=4))
        if target_timestamp > exp_timestamp:
            access_token = create_access_token(identity=get_jwt_identity())
            set_access_cookies(response, access_token)
        return response
    except (RuntimeError, KeyError) as e:
        return response


# Connect to exisiting database
conn = psycopg2.connect(
    database="recipedb", user="docker", password="docker", host="database"
)

# USER REGISTRATION
@app.route("/register", methods=["POST"])
def register():
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    name = request.json.get("name", None)

    if not username or not password:
        return {"msg": "Missing username or password"}, 401

    with conn.cursor() as db:
        db.execute(
            "SELECT * FROM recipe.user_credentials WHERE username = %s",
            (username,),
        )
        row = db.fetchall()
        if len(row) == 1:
            return {"msg": "username already exists"}, 401

        db.execute(
            "INSERT INTO recipe.user_credentials (username, password, name) VALUES (%s, %s, %s)",
            (username, generate_password_hash(password), name),
        )

    conn.commit()

    return {"msg": "registration success"}, 200


# LOGIN
@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username", None)
    password = request.json.get("password", None)

    if not username or not password:
        return jsonify({"msg": "Missing username or password"}), 400

    with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as db:
        db.execute(
            "SELECT * FROM recipe.user_credentials WHERE username = %s",
            (username,),
        )
        row = db.fetchall()
    conn.commit()

    if len(row) != 1:
        return {"msg": "Invalid username"}, 401

    if not check_password_hash(row[0]["password"], password):
        return {"msg": "Incorrect password"}, 401
    id = row[0]["id"]

    access_token = create_access_token(identity=id)
    response = jsonify(
        {
            "user": {
                "name": row[0]["name"],
                "username": row[0]["username"],
                "lastName": row[0]["last_name"],
            }
        }
    )

    set_access_cookies(response, access_token)
    return response, 200


# LOGOUT
@app.route("/logout", methods=["POST"])
def logout():
    response = jsonify({"msg": "logout successful"})
    unset_jwt_cookies(response)
    return response


# UPDATE USER_INFO
@app.route("/update_user", methods=["PATCH"])
@jwt_required()
def update_user():
    user_id = get_jwt_identity()
    if not (user_id):
        return {"msg": "unable to authenticate user"}, 401

    username = request.json.get("username", None)
    name = request.json.get("name", None)
    last_name = request.json.get("lastName", None)
    if not username or not name:
        return {"msg": "missing fields"}, 400

    with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as db:
        # check for username duplicate
        db.execute(
            "SELECT * FROM recipe.user_credentials WHERE username = %s",
            (username,),
        )
        row = db.fetchall()
        if len(row) == 1 and not row[0]["id"] == user_id:
            return {"msg": "username already exists"}, 400

        db.execute(
            "UPDATE recipe.user_credentials SET name = %s, username = %s, last_name = %s WHERE id = %s",
            (
                name,
                username,
                last_name,
                user_id,
            ),
        )

        db.execute(
            "SELECT * FROM recipe.user_credentials WHERE id = %s",
            (user_id,),
        )
        row = db.fetchall()

    conn.commit()
    response = jsonify(
        {
            "user": {
                "name": row[0]["name"],
                "username": row[0]["username"],
                "lastName": row[0]["last_name"],
            }
        }
    )

    return response, 200


# RESET PASSWORD
@app.route("/reset_password", methods=["PATCH"])
@jwt_required()
def reset_password():
    user_id = get_jwt_identity()
    if not (user_id):
        return {"msg": "unable to authenticate user"}, 401

    password = request.json.get("password", None)

    if not password:
        return {"msg": "please enter the new password"}, 400

    with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as db:
        db.execute(
            "UPDATE recipe.user_credentials SET password = %s WHERE id = %s",
            (
                generate_password_hash(password),
                user_id,
            ),
        )
    conn.commit()

    response = jsonify({"msg": "password reset successful"})

    return response, 200


# DELETE USER
@app.route("/delete_user", methods=["DELETE"])
@jwt_required()
def delete_user():
    user_id = get_jwt_identity()

    if not (user_id):
        return {"msg": "unable to authenticate user"}, 401

    with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as db:
        db.execute(
            "DELETE FROM recipe.user_credentials WHERE id = %s",
            (user_id,),
        )
        # how do I know if the delete is good? also delete favorite/shopping

    conn.commit()

    response = jsonify({"msg": "account deleted"})

    return response, 200


# Format the response for each recipe
def recipe_format(recipe):
    ingredient_list = []
    try:
        for k, v in recipe.items():
            if k.startswith("strIngredient") and v != "" and not v is None:
                ingredient_list.append(
                    f'{recipe[k.replace("strIngredient", "strMeasure")]} {v}'
                )
    except KeyError as e:
        return None
    instructions = [
        item.strip() for item in recipe["strInstructions"].split(".") if len(item) > 0
    ]
    return {
        "id": recipe["idMeal"],
        "area": recipe["strArea"],
        "category": recipe["strCategory"],
        "instructions": instructions,
        "name": recipe["strMeal"],
        "image": recipe["strMealThumb"],
        "ingredientList": ingredient_list,
    }


# FETCH ALL RECIPES
@app.route("/recipes", methods=["GET"])
def recipes():
    search = request.args.get("search")
    page = request.args.get("page")

    fetch_url = URL + f"search.php?s={search}"
    response = requests.get(url=fetch_url)
    data = response.json()
    if not data["meals"]:
        return {"allFetchedRecipes": [], "totalRecipes": 0}, 200

    recipes_list = [
        recipe_format(recipe) for recipe in data["meals"] if not recipe is None
    ]
    number_of_pages = math.ceil(len(recipes_list) / RECIPES_PER_PAGE)

    start_index = (int(page) - 1) * RECIPES_PER_PAGE
    results = recipes_list[start_index : start_index + RECIPES_PER_PAGE]

    return {
        "numOfPages": number_of_pages,
        "allFetchedRecipes": results,
        "totalRecipes": len(recipes_list),
    }, 200


# FETCH SINGLE RECIPE
@app.route("/recipes/<recipe_id>", methods=["GET"])
def single_recipe(recipe_id):
    fetch_url = URL + f"lookup.php?i={recipe_id}"
    print(fetch_url)
    response = requests.get(fetch_url)
    data = response.json()
    recipe = data["meals"]
    if not recipe:
        return {"msg": "Invalid"}, 200
    result = recipe_format(recipe[0])
    return {"msg": "Valid", "single_recipe": result}, 200


# ADD FAVORITES
@app.route("/add_favorite", methods=["POST"])
@jwt_required()
def add_favorite():
    user_id = get_jwt_identity()
    if not (user_id):
        return {"msg": "unable to authenticate user"}, 401

    id = request.json.get("id", None)
    name = request.json.get("name", None)
    category = request.json.get("category", None)
    image = request.json.get("image", None)

    if not id or not name or not category or not image:
        return {"msg": "missing recipe information"}, 400

    with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as db:
        db.execute(
            "INSERT INTO recipe.favorites (user_id, id, name, image, category) VALUES (%s, %s, %s, %s, %s) on conflict do nothing",
            (user_id, id, name, image, category),
        )

    conn.commit()

    response = jsonify({"msg": "recipe added to favorites"})

    return response, 200


# REMOVE FAVORITES
@app.route("/remove_favorite/<id>", methods=["DELETE"])
@jwt_required()
def remove_favorite(id):
    user_id = get_jwt_identity()
    if not (user_id):
        return {"msg": "unable to authenticate user"}, 401

    if not id:
        return {"msg": "missing recipe information"}, 400

    with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as db:
        try:
            db.execute(
                "DELETE FROM recipe.favorites WHERE id = %s AND user_id = %s",
                (id, user_id),
            )
        except:
            return jsonify({"msg": "recipe does not exist in the favorite list"}), 404

    conn.commit()

    response = jsonify({"msg": "recipe removed from favorites"})

    return response, 200


# FETCH FAVORITES
@app.route("/favorite", methods=["GET"])
@jwt_required()
def fetch_favorites():
    user_id = get_jwt_identity()
    sort = request.args.get("sort")
    page = request.args.get("page")

    with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as db:
        if sort == "a-z":
            db.execute(
                "SELECT id, name, image, category FROM recipe.favorites WHERE user_id = %s ORDER BY name",
                (user_id,),
            )
        else:
            db.execute(
                "SELECT id, name, image, category FROM recipe.favorites WHERE user_id = %s ORDER BY name DESC",
                (user_id,),
            )

        results = db.fetchall()

    conn.commit()
    recipes_list = [dict(result) for result in results]
    id_list = [result["id"] for result in results]
    number_of_pages = math.ceil(len(recipes_list) / RECIPES_PER_PAGE)
    start_index = (int(page) - 1) * RECIPES_PER_PAGE
    results = recipes_list[start_index : start_index + RECIPES_PER_PAGE]

    response = jsonify(
        {
            "favoriteList": results,
            "idList": id_list,
            "totalRecipes": len(recipes_list),
            "numOfPages": number_of_pages,
        }
    )

    return response, 200


# ADD TO LIST
@app.route("/add_list", methods=["POST"])
@jwt_required()
def add_list():
    user_id = get_jwt_identity()
    if not (user_id):
        return {"msg": "unable to authenticate user"}, 401

    id = request.json.get("id", None)
    name = request.json.get("name", None)
    ingredients = request.json.get("ingredientList", None)

    if not id or not name or not ingredients:
        return {"msg": "missing recipe information"}, 400

    with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as db:
        for ingredient in ingredients:
            db.execute(
                "INSERT INTO recipe.shopping_list (user_id, recipe_id, recipe_name, ingredients) VALUES (%s, %s, %s, %s) on conflict do nothing",
                (
                    user_id,
                    id,
                    name,
                    ingredient,
                ),
            )

    conn.commit()

    response = jsonify({"msg": "ingredients added to grocery list"})

    return response, 200


# FETCH LIST
@app.route("/fetch_list", methods=["GET"])
@jwt_required()
def fetch_list():
    user_id = get_jwt_identity()

    with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as db:
        db.execute(
            "SELECT recipe_id, recipe_name, ingredients FROM recipe.shopping_list WHERE user_id = %s",
            (user_id,),
        )
        results = db.fetchall()

    conn.commit()

    shopping_list = [
        {
            "id": result["recipe_id"],
            "name": result["recipe_name"],
            "ingredient": result["ingredients"],
        }
        for result in results
    ]
    names = list(set([result["recipe_name"] for result in results]))

    response = jsonify({"shoppingList": shopping_list, "names": names})

    return response, 200


# DELETE LIST
@app.route("/delete_list", methods=["DELETE"])
@jwt_required()
def delete_list():
    user_id = get_jwt_identity()

    with conn.cursor() as db:
        db.execute("DELETE FROM recipe.shopping_list WHERE user_id = %s", (user_id,))

    conn.commit()

    response = jsonify({"msg": "list cleared"})

    return response, 200


# DELETE ITEM
@app.route("/delete_item", methods=["DELETE"])
@jwt_required()
def delete_item():
    user_id = get_jwt_identity()
    id = request.args.get("id")
    ingredient = request.args.get("ingredient")

    with conn.cursor() as db:
        db.execute(
            "DELETE FROM recipe.shopping_list WHERE user_id = %s AND recipe_id = %s AND ingredients = %s",
            (user_id, id, ingredient),
        )

    conn.commit()

    response = jsonify({"msg": "item removed"})

    return response, 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050)
