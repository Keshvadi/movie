import json
import os
from typing import Dict

from config import is_file_exist


class Player():
    def __init__(self,
                 render_id = "",
                 player_id = "",
                 origin_url = "",
                 frame_url = "",
                 frame_title = "",
                 surface_layer_mode = "",
                 url = "",
                 found_audio_stream = "",
                 audio_codec_name = "",
                 found_video_stream = "",
                 video_codec_name = "",
                 audio_decoder = "",
                 video_decoder = "",
                 audio_buffering_state = "",
                 video_buffering_state = "",
                 height = "",
                 width = "",
                 for_suspended_start = "",
                 pipeline_buffering_state = "",
                 duration = 0,
                 last_event = "",
                 events = []
                 ):
        """

        :type events: Event
        """
        self.render_id = render_id
        self.player_id = player_id
        self.origin_url = origin_url
        self.frame_url = frame_url
        self.frame_title = frame_title
        self.surface_layer_mode = surface_layer_mode
        self.url = url
        self.found_audio_stream = found_audio_stream
        self.audio_codec_name = audio_codec_name
        self.found_video_stream = found_video_stream
        self.video_codec_name = video_codec_name
        self.audio_decoder = audio_decoder
        self.video_decoder = video_decoder
        self.audio_buffering_state = audio_buffering_state
        self.video_buffering_state = video_buffering_state
        self.height = height
        self.width = width
        self.for_suspended_start = for_suspended_start
        self.pipeline_buffering_state = pipeline_buffering_state
        self.duration = duration
        self.last_event = last_event
        self.events = events
class Event():
    def __init__(self, time=None, key=None, value=None):
        self.time = time
        self.key = key
        self.value = value

def create_player_log(file_name):
    print("Reading media-internals.txt ...")
    is_file_exist(file_name)
    try:
        with open(file_name) as player_file:
            player_info = json.load(player_file)
    except:
        print("Error: %s is not in the appropriate JSON format.\n\n")%(file_name)
        exit(0)

    lst_players: Dict[int, Player] = {}
    player_count = 0
    for i in player_info:
        p = Player()
        player_count +=1
        for j in i:
            if str(j) == "properties":
                for k in i[j]:
                    temp = str(i[j][k])
                    if k == "render_id":
                        p.render_id = temp
                        continue
                    if k=="player_id":
                        p.player_id = temp
                        continue
                    if k=="origin_url":
                        p.origin_url = temp
                        continue
                    if k=="frame_url":
                        p.frame_url = temp
                        continue
                    if k=="frame_title":
                        p.frame_title = temp
                        continue
                    if k=="surface_layer_mode":
                        p.surface_layer_mode = temp
                        continue
                    if k=="url":
                        p.url = temp
                        continue
                    if k=="found_audio_stream":
                        p.found_audio_stream = temp
                        continue
                    if k=="audio_codec_name":
                        p.audio_codec_name = temp
                        continue
                    if k=="found_video_stream":
                        p.found_video_stream = temp
                        continue
                    if k=="video_codec_name":
                        p.video_codec_name = temp
                        continue
                    if k=="audio_decoder":
                        p.audio_decoder = temp
                        continue
                    if k=="video_decoder":
                        p.video_decoder = temp
                        continue
                    if k=="audio_buffering_state":
                        p.audio_buffering_state = temp
                        continue
                    if k=="video_buffering_state":
                        p.video_buffering_state = temp
                        continue
                    if k=="height":
                        p.height = temp
                        continue
                    if k=="width":
                        p.width = temp
                        continue
                    if k=="for_suspended_start":
                        p.for_suspended_start = temp
                        continue
                    if k=="pipeline_buffering_state":
                        p.pipeline_buffering_state = temp
                        continue
                    if k=="duration":
                        p.duration = temp
                        continue
                    if k=="event":
                        p.last_event = temp
                        continue
            if str(j) == "events":
                p.events = []
                for k in i[j]:
                    # e = []
                    e = Event()
                    for m in k:
                        if m == "time":
                            # e.append(str(k[m]))
                            e.time = str(k[m])
                            continue
                        if m == "key":
                            # e.append(str(k[m]))
                            e.key = str(k[m])
                            continue
                        if m == "value":
                            # e.append(str(k[m]))
                            e.value = str(k[m])
                            continue
                    p.events.append(e)
                lst_players[player_count] = p
                break
    player_file.close()
    print("Done! %s player created."%(len(lst_players)))
    return lst_players

def show_player_logs(lst_players:Dict[int, Player]):
    headers = ["Event Time", "Key", "Value"]
    data_test = {}
    n = 0
    for i in lst_players:
        for j in lst_players[i].events:
            temp = []
            temp.append(j.time)
            temp.append(j.key)
            temp.append(j.value)
            data_test[j.time] = temp

    return headers, data_test

def read_event():
    pass







