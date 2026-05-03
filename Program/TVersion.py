# Copyright (c) RedTiger by Loxy0devlp
# Licensed under the MIT License.
# See LICENSE file in the project root for full license text.

from Config.Utils import *

def Version():
    Title("Version")
    print(f"{red}Developer : {white}{developer}")
    print(f"{red}Name      : {white}{tool_name}")
    print(f"{red}Version   : {white}v{tool_version}")
    print(f"{red}License   : {white}{tool_license}")
    print(f"{red}Github    : {white}https://{tool_github}")
    print(f"{red}Website   : {white}https://{website}")
    print(f"{red}Telegram  : {white}https://{telegram}")
    print(f"{red}Guns.lol  : {white}https://{gunslol}\n")
    Continue()
    Reset()