import asyncio
import json
from random import randint
from datetime import datetime, timedelta

import aiofiles


async def data_generator(rows: int = 1000):
    async with aiofiles.open("static/datasource-1.json", 'r+') as json_file:
        try:
            data = json.loads(await json_file.read())
        except json.decoder.JSONDecodeError:
            data = {}

        if not data.get('traffic'):
            data['traffic'] = []

        date_iteration = 1
        for _ in range(0, rows):
            new_traffic_row = {
                'created_at': str(datetime.now().date() - timedelta(days=date_iteration)),
                'count': randint(9000, 18686)
            }

            data['traffic'].insert(0, new_traffic_row)
            date_iteration += 1

    async with aiofiles.open("datasource-1.json", 'w') as json_file:
        data = json.dumps(data, indent=4)
        await json_file.write(data)


if __name__ == '__main__':
    asyncio.run(
        data_generator()
    )