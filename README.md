## Initial TODO:

Backend:
- API: 
	- send_nfc_event (user_id, tag_id) 				DONE
	- send_event (timestamp, user_id, tag_id)
	- retrieve_hours_for_month (user_id, month) 	DONE
	- set_user_name (user_id, user_name) 			DONE
	- get_user_id (user_name) 						DONE
	- register_new_tag (tag_id, location) 			DONE

- DB:
	- users: user_id, user_name 					DONE
	- tags: tag_id, location 						DONE
	- hours: timestamp, user_id, tag_id 			DONE
	
- No backend security planned for now.

App:
- Intent filter										DONE
- Request sending									DONE
- Monthly overview									DONE x3

Tag:
- write password protection:
	- secret_key is the password
- write URL that opens the app. Also retrieve tag_id.

## TODO on 17.3.2020:

- Make delimiter brighter each start of the week
- Bugs if there is not entry for month X			DONE
- Reverse days and months							DONE
- Finish title bar									
	- Button for 2 types of worktime summation
	- Changes in regards to whether worker is checked out or not.