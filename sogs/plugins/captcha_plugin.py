from sogs.plugins.captcha import CaptchaManager, EmojiCaptcha
from sogs.plugins_interface import *


def _delete(_dict, outer_key, inner_key):
    del _dict[outer_key][inner_key]
    if len(_dict[outer_key]) == 0:
        del _dict[outer_key]


def _set(_dict, outer_key, inner_key, value):
    if outer_key not in _dict:
        _dict[outer_key] = dict()
    _dict[outer_key][inner_key] = value


class CaptchaPlugin(Plugin):

    def __init__(
            self,
            sogs_address,
            sogs_pubkey,
            privkey,
            pubkey,
            display_name,
            retry_limit=3,
            refresh_timeout=60,
            retry_timeout=120,
            write_timeout=120,
    ):
        self.refresh_reaction = "\U0001F504"
        self.pending_requests = {}  # map {session_id : {room_token : msg_id}}
        self.pending_delete = {}  # map {session_id : {room_token : [msg_id]}}
        self.retry_jail = {}  # map {session_id: {room_token : Timestamp}}
        self.retry_limit = retry_limit
        self.retry_timeout = retry_timeout
        self.refresh_timeout = refresh_timeout
        self.write_timeout = write_timeout
        self.challenges = {}  # map {session_id : {room_token : (Captcha, Timestamp)}}
        self.retry_record = {}  # map {session_id: {room_token : Int}}
        self.captcha_manager = CaptchaManager(initial_count=200)

        Plugin.__init__(self, sogs_address, sogs_pubkey, privkey, pubkey, display_name)
        self.register_request_read_handler(self.handle_request_read)

    def handle_request_read(self, req):
        room_token = req[b'room_token']
        room_name = req[b'room_name'].decode('utf-8')
        session_id = req[b'session_id']
        if session_id in self.retry_record and room_token in self.retry_record[session_id]:
            if self.retry_record[session_id][room_token] >= self.retry_limit:
                return bt_serialize("JAIL FOREVER")

        if session_id in self.retry_jail and room_token in self.retry_jail[session_id]:
            if time() > self.retry_jail[session_id][room_token]:
                _delete(self.retry_jail, session_id, room_token)
            else:
                return bt_serialize("JAIL")

        if session_id in self.pending_requests and room_token in self.pending_requests[session_id]:
            return bt_serialize("OK")
        print(f"request_read from {session_id}, id={req[b'user_id']}, room={room_token}")
        return self.post_challenge(room_token, session_id, room_name)

    def post_challenge(self, room_token, session_id, room_name):
        try:
            if session_id in self.pending_delete and room_token in self.pending_delete[session_id]:
                self.delete_messages(self.pending_delete[session_id][room_token])
                _delete(self.pending_delete, session_id, room_token)

            self.refresh_capcha_handler(session_id, room_token)
            captcha = self.challenges[session_id][room_token][0]
            file_path = captcha.file_name
            file_meta = self.upload_file(file_path, room_token)

            refresh_times_left = self.retry_limit
            if session_id in self.retry_record and room_token in self.retry_record[session_id]:
                refresh_times_left -= self.retry_record[session_id][room_token]

            body = ""

            # Case 1: User is coming to the community for the first time
            if refresh_times_left == self.retry_limit:
                body += (f"Solve this CAPTCHA to read and send messages in {room_name}. ")

            # Case 1 and 2: User is coming to the community for the first time or has refreshed but hasn't reached the limit
            if refresh_times_left > 0:
                body += (f"React to the image with the emoji shown in the image. ")
                if refresh_times_left == self.retry_limit:
                    body += (f"You can refresh the CAPTCHA once every {self.refresh_timeout} seconds by reacting with \U0001F504. ")
                body += f"You have {refresh_times_left} time{'s' if refresh_times_left > 1 else ''} remaining to refresh."

            # Case 3: User has refreshed and has reached the limit
            elif refresh_times_left == 0:
                body += (f"You have hit the refresh limit. "
                        f"Please try to solve the current CAPTCHA by reacting with the emoji in the image.")

            msg_id = self.post_message(
                room_token,
                body,
                whisper_target=session_id,
                no_plugins=True,
                files=[file_meta,]
            )
            print(f'Challenge message id: {msg_id}')
            if msg_id:
                if refresh_times_left > 0:
                    react_resp = self.post_reactions(
                        room_token, msg_id, self.refresh_reaction
                    )
                    print(f'React response: {react_resp}')
                    if b'error' in react_resp:
                        print(f"Error adding reactions to whisper: {react_resp[b'error']}")
                        return bt_serialize("ERROR")
                _set(self.pending_requests, session_id, room_token, msg_id)
        except:
            import traceback
            print(traceback.format_exc())
        return bt_serialize("OK")

    def refresh_capcha_handler(self, session_id, room_token):
        _set(self.challenges, session_id, room_token, (self.captcha_manager.refresh(), time()))

    def handle_refresh(self, msg_id, session_id, room_token, room_name):
        if session_id not in self.retry_record or room_token not in self.retry_record[session_id]:
            _set(self.retry_record, session_id, room_token, 0)
        if self.retry_record[session_id][room_token] >= self.retry_limit:
            return

        timeout = int(self.refresh_timeout - (time() - self.challenges[session_id][room_token][1]))
        if timeout > 0:
            unreact_resp = self.remove_reactions(
                room_token, msg_id, self.refresh_reaction
            )
            print(f'React response: {unreact_resp}')
            msg_id = self.post_message(
                room_token,
                f"You can refresh the CAPTCHA in {timeout} second{'s' if timeout > 1 else ''}.",
                whisper_target=session_id,
                no_plugins=True
            )
            print(f'Refresh timeout message id: {msg_id}')
            if session_id not in self.pending_delete or room_token not in self.pending_delete[session_id]:
                _set(self.pending_delete, session_id, room_token, [])
            self.pending_delete[session_id][room_token].append(msg_id)
        else:
            self.retry_record[session_id][room_token] += 1
            self.delete_message(msg_id)
            self.post_challenge(room_token, session_id, room_name)

    def handle_success(self, msg_id, session_id, room_token, room_name):
        if self.write_timeout == 0:
            self.post_message(
                room_token,
                f"Congratulations! You can now read and send messages in {room_name}.",
                whisper_target=session_id,
                no_plugins=True,
            )
            # Grant read and write permission immediately after receiving the correct reaction
            self.set_user_room_permissions(
                room_token=room_token, user_session_id=session_id, sec_from_now=None, read=True, write=True
            )
        else:
            self.post_message(
                room_token,
                f"Congratulations! You will be able to read and send messages in {self.write_timeout} seconds.",
                whisper_target=session_id,
                no_plugins=True,
            )
            # Grant read permission immediately after receiving the correct reaction
            self.set_user_room_permissions(
                room_token=room_token, user_session_id=session_id, sec_from_now=None, read=True
            )
            # Grant write permission after {self.write_timeout} time
            self.set_user_room_permissions(
                room_token=room_token, user_session_id=session_id, sec_from_now=self.write_timeout, write=True
            )

        self.delete_message(msg_id)
        _delete(self.pending_requests, session_id, room_token)

    def handle_failure(self, msg_id, session_id, room_token):
        if session_id not in self.retry_record or room_token not in self.retry_record[session_id]:
            _set(self.retry_record, session_id, room_token, 0)
        self.retry_record[session_id][room_token] += 1
        retry_times_left = self.retry_limit - self.retry_record[session_id][room_token]
        remaining = f"{retry_times_left} " + "attempt" + ("s" if retry_times_left > 1 else "")
        body = (f"That was the wrong emoji. You’ll receive a new CAPTCHA in {self.retry_timeout} seconds. "
                f"You have {remaining} remaining.") if retry_times_left > 0 else \
            (f"That was the wrong emoji. You have reached the maximum number of attempts. "
             f"Contact an Administrator of the community for further assistance")

        response_msg_id = self.post_message(
            room_token,
            body,
            whisper_target=session_id,
            no_plugins=True,
        )
        _set(self.retry_jail, session_id, room_token, (time() + self.retry_timeout))
        if session_id not in self.pending_delete or room_token not in self.pending_delete[session_id]:
            _set(self.pending_delete, session_id, room_token, [])
        self.pending_delete[session_id][room_token].append(response_msg_id)

        self.delete_message(msg_id)
        _delete(self.pending_requests, session_id, room_token)

    def reaction_posted(self, m: oxenmq.Message):
        req = bt_deserialize(m.dataview()[0])
        print(f"reaction_posted, req = {req}")
        msg_id = req[b'msg_id']
        session_id = req[b'session_id']
        room_token = req[b'room_token']
        room_name = req[b'room_name'].decode('utf-8')
        if (
                session_id in self.pending_requests
                and room_token in self.pending_requests[session_id]
                and msg_id == self.pending_requests[session_id][room_token]
                and session_id in self.challenges
                and room_token in self.challenges[session_id]
                and self.challenges[session_id][room_token] is not None
        ):
            print(f"reaction_posted, correct session_id, room, and msg_id")
            reaction = req[b'reaction'].decode('utf-8')

            if reaction == self.refresh_reaction:
                print(f"{session_id} request refreshing challenge.")
                self.handle_refresh(msg_id, session_id, room_token, room_name)
            elif reaction == self.challenges[session_id][room_token][0].answer:
                print(f"Granting permissions to {session_id} for room with token {room_token}")
                self.handle_success(msg_id, session_id, room_token, room_name)
            else:
                print(f"Wrong answer! Can't grant permission to {session_id}")
                self.handle_failure(msg_id, session_id, room_token)


