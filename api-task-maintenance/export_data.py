import json
import psycopg2
import psycopg2.extras
import uuid
from dataclasses import dataclass


@dataclass()
class Region:
    country: str
    title: str


@dataclass()
class Device:
    brand: uuid.UUID
    name: str
    device: str
    model: str


@dataclass()
class LastName:
    brand: uuid.UUID
    name: str
    device: str
    model: str


# Подключение к существующей базе данных
psycopg2.extras.register_uuid()

connection = psycopg2.connect(user="iplo",
                              password="171202",
                              host="127.0.0.1",
                              port="5432",
                              database="docker_android")


with open('json/geolocation/ua-cities.json', 'r', encoding='utf-8') as file:
    data = json.load(file)
    count_city = 0
    cursor = connection.cursor(cursor_factory=psycopg2.extras.DictCursor)

    for item in data[0].get('regions'):
        if item.get('name') in ['Донецкая область', 'Луганская область', 'Автономная Республика Крым']:
            continue

        query = f"SELECT * FROM workers_region WHERE title = '{item.get('name')}';"
        cursor.execute(query)

        region = cursor.fetchone()
        region_id = uuid.UUID(str(region['id']))

        for city in item.get('cities'):
            count_city += 1

            query_insert = """INSERT INTO workers_city (id, title, region_id, latitude, longitude) 
                           VALUES (%s, %s, %s, %s, %s);"""

            values = (uuid.uuid4(), city.get('name'), region_id, city.get('lat'), city.get('lng'))

            cursor.execute(query_insert, values)
            connection.commit()

    print(count_city)
# with open('json/surnames_table.json', 'r', encoding='utf-8') as file:
#     data = json.load(file)
#
#     print(data)
#     for item in data:
#         print(item)
        # query = "INSERT INTO workers_androidbuildversion (id, build, tag, version_android) VALUES (%s, %s, %s, %s) ON CONFLICT (build) DO NOTHING;"
        # values = (uuid.uuid4(), item.get('Build ID'), item.get('Tag'), item.get('Version'))
        #
        # cursor.execute(query, values)
        # connection.commit()


cursor.close()
connection.close()
