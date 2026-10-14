"""Local display names verified against HealthKit 23T240; not Apple UI strings.

Evidence: analysis/workout-activity-names-23T240.md. Unknown IDs stay numeric.
"""
import math

from apple_codec import one, protobuf


ACTIVITIES = {
    1: 'American Football',
    2: 'Archery',
    3: 'Australian Football',
    4: 'Badminton',
    5: 'Baseball',
    6: 'Basketball',
    7: 'Bowling',
    8: 'Boxing',
    9: 'Climbing',
    10: 'Cricket',
    11: 'Cross Training',
    12: 'Curling',
    13: 'Cycling',
    14: 'Dance',
    15: 'Dance Inspired Training',
    16: 'Elliptical',
    17: 'Equestrian Sports',
    18: 'Fencing',
    19: 'Fishing',
    20: 'Functional Strength Training',
    21: 'Golf',
    22: 'Gymnastics',
    23: 'Handball',
    24: 'Hiking',
    25: 'Hockey',
    26: 'Hunting',
    27: 'Lacrosse',
    28: 'Martial Arts',
    29: 'Mind and Body',
    30: 'Mixed Metabolic Cardio Training',
    31: 'Paddle Sports',
    32: 'Play',
    33: 'Preparation And Recovery',
    34: 'Racquetball',
    35: 'Rowing',
    36: 'Rugby',
    37: 'Running',
    38: 'Sailing',
    39: 'Skating Sports',
    40: 'Snow Sports',
    41: 'Soccer',
    42: 'Softball',
    43: 'Squash',
    44: 'Stair Climbing',
    45: 'Surfing Sports',
    46: 'Swimming',
    47: 'Table Tennis',
    48: 'Tennis',
    49: 'Track and Field',
    50: 'Traditional Strength Training',
    51: 'Volleyball',
    52: 'Walking',
    53: 'Water Fitness',
    54: 'Water Polo',
    55: 'Water Sports',
    56: 'Wrestling',
    57: 'Yoga',
    58: 'Barre',
    59: 'Core Training',
    60: 'Cross Country Skiing',
    61: 'Downhill Skiing',
    62: 'Flexibility',
    63: 'HIIT',
    64: 'Jump Rope',
    65: 'Kickboxing',
    66: 'Pilates',
    67: 'Snowboarding',
    68: 'Stairs',
    69: 'Step Training',
    70: 'Wheelchair Walk Pace',
    71: 'Wheelchair Run Pace',
    72: 'Tai Chi',
    73: 'Mixed Cardio',
    74: 'Hand Cycling',
    75: 'Disc Sports',
    76: 'Fitness Gaming',
    77: 'Cardio Dance',
    78: 'Social Dance',
    79: 'Pickleball',
    80: 'Cooldown',
    82: 'Swim Bike Run',
    83: 'Transition',
    84: 'Underwater Diving',
    3000: 'Other',
}


def workout_label(activity, metadata=None):
    label = ACTIVITIES.get(activity, f'Type {activity}' if activity is not None else 'Not reported')
    # Only Walking gets an environment label until other UI variants are verified.
    if activity != 52 or not isinstance(metadata, bytes):
        return label
    try:
        flags = []
        for raw in protobuf(metadata).get(1, []):
            pair = protobuf(raw)
            if one(pair, 1) != b'HKIndoorWorkout':
                continue
            values = pair.get(4, []) + pair.get(5, [])
            if (len(values) != 1 or any(n in pair for n in (2, 3, 6, 7))
                    or type(values[0]) not in (int, float)
                    or not math.isfinite(values[0]) or values[0] not in (0, 1)):
                return label
            flags.append(bool(values[0]))
        if len(flags) == 1:
            return 'Indoor Walk' if flags[0] else 'Outdoor Walk'
    except (ValueError, TypeError, OverflowError):
        pass
    return label
