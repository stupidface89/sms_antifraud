import dataclasses
import uuid
import sqlite3
import psycopg2

from psycopg2.extensions import connection as postgresql_connection
from psycopg2.extras import DictCursor

from dataclasses import dataclass, field
from contextlib import contextmanager


@dataclass
class FirstName:
    value: str
    gender: str
    id: uuid.UUID = field(default_factory=uuid.uuid4)


@dataclass
class FirstNameCountry:
    first_name: uuid.UUID
    country: uuid.UUID
    id: uuid.UUID = field(default_factory=uuid.uuid4)


@contextmanager
def conn_context(path_to_db: str) -> sqlite3.connect:
    conn = sqlite3.connect(path_to_db)
    conn.row_factory = sqlite3.Row
    yield conn
    conn.close()


def take_data(sql_connection: sqlite3.connect, table_name: str):
    cursor = sql_connection.cursor()
    cursor.execute(f"SELECT * FROM {table_name}")
    data = cursor.fetchall()
    yield data


def import_data(pg_connection: psycopg2.extensions.connection, obj: dataclasses.dataclass, table_name: str):
    cursor = pg_connection.cursor()

    fields = tuple(i for i in obj.__annotations__.keys())
    print(', '.join(fields,))
    first_name_value = obj.value

    cursor.execute(f"INSERT INTO {table_name} ({', '.join(fields,)}) VALUES {obj.value, obj.gender, obj.id} ON CONFLICT DO NOTHING")


if __name__ == "__main__":
    dsl = {'dbname': 'docker_android', 'user': 'iplo', 'password': '171202', 'host': '127.0.0.1', 'port': 5433}
    with conn_context('../db.sqlite3') as sqlite_connect, psycopg2.connect(**dsl, cursor_factory=DictCursor) as pg_connect:
        sqlite_data = take_data(sqlite_connect, 'accounts_firstname')

        for item in sqlite_data:
            for ata in item:
                #name_id = dict(item).get('id')
                inst = dict(ata)

                first_name_inst = FirstName(gender=inst.get('gender'), value=inst.get('value'))
                #first_name_country_inst = FirstNameCountry(first_name=name_id,
                #                                           country=uuid.UUID('b80af2e8-7e0f-4128-b587-5f70104d2bde'))

                print(dict(ata).get('id'))
                import_data(pg_connect, obj=first_name_inst, table_name='workers_first_name')




