"""
Helper functions for Recipe Tracker.
"""

# Unit conversion factors to grams/ml as base
UNIT_CONVERSIONS = {
    # Volume
    "tsp":   {"ml": 4.929, "tbsp": 0.333, "cup": 0.0208},
    "tbsp":  {"ml": 14.787, "tsp": 3, "cup": 0.0625},
    "cup":   {"ml": 236.588, "tbsp": 16, "tsp": 48},
    "fl oz": {"ml": 29.574, "cup": 0.125},
    "pint":  {"ml": 473.176, "cup": 2},
    "quart": {"ml": 946.353, "cup": 4},
    "liter": {"ml": 1000, "cup": 4.227},
    "ml":    {"tsp": 0.203, "tbsp": 0.068, "cup": 0.00423},
    # Weight
    "oz":    {"g": 28.3495, "lb": 0.0625},
    "lb":    {"g": 453.592, "oz": 16},
    "g":     {"oz": 0.03527, "kg": 0.001},
    "kg":    {"g": 1000, "lb": 2.20462},
}

CATEGORIES = [
    "Breakfast", "Lunch", "Dinner", "Pasta", "Chinese",
    "Healthy", "Mexican", "Italian", "Seafood", "Soup",
    "Salad", "Dessert", "Vegetarian", "Vegan", "Quick & Easy", "Other"
]

CATEGORY_ICONS = {
    "Breakfast": "bi-cup-hot",
    "Lunch": "bi-sun",
    "Dinner": "bi-moon-stars",
    "Pasta": "bi-circle",
    "Chinese": "bi-star",
    "Healthy": "bi-heart-pulse",
    "Mexican": "bi-fire",
    "Italian": "bi-flag",
    "Seafood": "bi-water",
    "Soup": "bi-cup-straw",
    "Salad": "bi-leaf",
    "Dessert": "bi-cake",
    "Vegetarian": "bi-tree",
    "Vegan": "bi-flower1",
    "Quick & Easy": "bi-lightning",
    "Other": "bi-grid",
}

CATEGORY_COLORS = {
    "Breakfast": "warning",
    "Lunch": "info",
    "Dinner": "primary",
    "Pasta": "danger",
    "Chinese": "danger",
    "Healthy": "success",
    "Mexican": "warning",
    "Italian": "success",
    "Seafood": "info",
    "Soup": "secondary",
    "Salad": "success",
    "Dessert": "danger",
    "Vegetarian": "success",
    "Vegan": "success",
    "Quick & Easy": "warning",
    "Other": "secondary",
}


def scale_ingredients(ingredients, original_servings, new_servings):
    """Scale ingredient amounts based on servings change."""
    if original_servings <= 0:
        return ingredients
    factor = new_servings / original_servings
    scaled = []
    for ing in ingredients:
        try:
            original_amount = float(ing["amount"])
            new_amount = original_amount * factor
            # Format nicely
            if new_amount == int(new_amount):
                formatted = str(int(new_amount))
            else:
                formatted = f"{new_amount:.2f}".rstrip("0").rstrip(".")
            scaled.append({**ing, "amount": formatted})
        except (ValueError, TypeError):
            scaled.append(ing)
    return scaled


def convert_unit(amount, from_unit, to_unit):
    """Convert an amount from one unit to another."""
    from_unit = from_unit.lower().strip()
    to_unit = to_unit.lower().strip()
    if from_unit == to_unit:
        return amount
    if from_unit in UNIT_CONVERSIONS and to_unit in UNIT_CONVERSIONS[from_unit]:
        return amount * UNIT_CONVERSIONS[from_unit][to_unit]
    return None
