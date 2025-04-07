import aiohttp
import asyncio

import logging

API_TOKEN = '1260165991:AAGyCbN4DM64GEpOEqy4FXZdJIRcigx9ixk'


async def telegram_send_message(message: str):
    async with aiohttp.ClientSession() as session:
        chat_id = '-1001186975794'
        url = f'https://api.telegram.org/bot{API_TOKEN}/sendMessage?chat_id={chat_id}&text={message}'
        async with session.get(url) as resp:
            response = await resp.json()


# def send_message(message: str, chat_id):
#     url = f'https://api.telegram.2org/bot{API_TOKEN}/sendMessage?chat_id={chat_id}&text={message}'
#     try:
#         response = requests.get(url, timeout=3)
#     except Exception as e:
#         logging.error(e)

