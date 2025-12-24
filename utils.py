import json
import os
from colorama import Fore, Style,init

init(autoreset=True)

def load_config():
    default_config={
        "timeout":1,
        "max_threads":50,
        "crawl_depth":2,
        "user_agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
    }
    config_path="config.json"
    if os.path.exists(config_path):
        try:
            with open(config_path,'r') as f:
                user_config=json.load(f)
                default_config.update(user_config)
        except Exception as e:
            pass
    return default_config
def print_colored(test,color="green"):
    colors={
        "green":Fore.GREEN,
        "red":Fore.RED,
        "yellow":Fore.YELLOW,
        "blue":Fore.BLUE,
        "cyan":Fore.CYAN,
        "magenta":Fore.MAGENTA,
        "white":Fore.WHITE
    }
    color_code=colors.get(color.lower(),Fore.GREEN)
    print(f"{color_code}{test}{Style.RESET_ALL}")

def save_results(results,filename):
    os.makedirs("results",exist_ok=True)
    with open(f"{filename}",'w') as f:
        json.dump(results,f,indent=2)
    print_colored(f"结果已保存到 {filename}","cyan")
    