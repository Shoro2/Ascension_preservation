"""Canonical WoW 3.3.5a per-race character data for the local Ascension archive world
server: native display IDs (model shown in char-select and in-world) and starting
positions (map / x / y / z / orientation / zone).

Values are the stock 3.3.5a DBC / playercreateinfo constants -- good enough to place a
freshly-made classless character in its racial starting valley. Ascension-custom starts
can be datamined later; this just gets the client in-world.
"""

# race id -> (male_display_id, female_display_id)
RACE_DISPLAY = {
    1:  (49, 50),        # Human
    2:  (51, 52),        # Orc
    3:  (53, 54),        # Dwarf
    4:  (55, 56),        # Night Elf
    5:  (57, 58),        # Undead (Scourge)
    6:  (59, 60),        # Tauren
    7:  (1563, 1564),    # Gnome
    8:  (1478, 1479),    # Troll
    10: (15476, 15475),  # Blood Elf  (female id < male id -- intentional)
    11: (16125, 16126),  # Draenei
}

# race id -> (map, x, y, z, orientation, zoneId)
RACE_START = {
    1:  (0,   -8949.95,  -132.493,  83.5312,  0.0,      12),    # Elwynn / Northshire
    2:  (1,   -618.518,  -4251.67,  38.718,   0.0,      14),    # Durotar / Valley of Trials
    3:  (0,   -6240.32,   331.033,  382.758,  6.17716,  1),     # Dun Morogh / Coldridge
    4:  (1,   10311.3,    832.463,  1326.41,  5.69632,  141),   # Teldrassil / Shadowglen
    5:  (0,   1676.71,    1678.31,  121.67,   2.70526,  85),    # Tirisfal / Deathknell
    6:  (1,   -2917.58,  -257.98,   52.9968,  0.0,      215),   # Mulgore / Camp Narache
    7:  (0,   -6240.32,   331.033,  382.758,  6.17716,  1),     # Dun Morogh / Coldridge (shared)
    8:  (1,   -618.518,  -4251.67,  38.718,   0.0,      14),    # Durotar / Valley of Trials (shared)
    10: (530, 10349.6,   -6357.29,  33.4026,  5.31605,  3431),  # Eversong / Sunstrider Isle
    11: (530, -3961.64,  -13931.2,  100.615,  2.08364,  3524),  # Azuremyst / Ammen Vale
}

# race id -> player FactionTemplateID (ChrRaces.FactionID). Only affects how other
# units are coloured relative to the player; not rendering-critical for self.
RACE_FACTION = {
    1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6, 7: 115, 8: 116, 10: 1610, 11: 1629,
}

# WoW power types (UNIT_FIELD_BYTES_0 byte 3). Classless chars default to a sane power.
POWER_MANA, POWER_RAGE, POWER_FOCUS, POWER_ENERGY = 0, 1, 2, 3

# stock class -> power type (used only to fill UNIT_FIELD_BYTES_0 / power fields)
CLASS_POWER = {
    1: POWER_RAGE,     # Warrior
    2: POWER_MANA,     # Paladin
    3: POWER_FOCUS,    # Hunter (pet focus; player uses mana pre-Cata but focus id here is fine as display)
    4: POWER_ENERGY,   # Rogue
    5: POWER_MANA,     # Priest
    6: POWER_RAGE,     # Death Knight (runic power = 6, but rage slot works for display)
    7: POWER_MANA,     # Shaman
    8: POWER_MANA,     # Mage
    9: POWER_MANA,     # Warlock
    11: POWER_MANA,    # Druid
}


def display_for(race, gender):
    """gender: 0 = male, 1 = female. Falls back to Human if race unknown."""
    male, female = RACE_DISPLAY.get(race, RACE_DISPLAY[1])
    return female if gender == 1 else male


def start_for(race):
    return RACE_START.get(race, RACE_START[1])


def power_for(clas):
    return CLASS_POWER.get(clas, POWER_MANA)
