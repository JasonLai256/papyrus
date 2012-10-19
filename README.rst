Papyrus
=======
Papyrus is a safely (use AES256 encrypt/decrypt) simple cmd program that manage the infomation of passwords.


Usage
-----

Support Commands:

  - ls::
      Usage: ls {groups | records | `group_name` | `group_id`}

      selected args:
        - `group`:  literal key word, show all the groups
        - `records`:  literal key word, show all the records
        - group_name: group name, show all the records in the specific group
        - group_id:  group id, show all the records in the specific group
      
      List all the groups or records existing in the current program.
      
  - info::
      Usage: info record_id

      args:
        - record_id:  the id of the record, `ls` is a useful command for lookup the record id.

      Show the full infomation about specific record.

  - add::
      Usage: add group item value [note]

      args:
        - group:  group name of the record.
        - item:   item name of the record.
        - value:  value of the record. well, there is the place store the password.
        - note(optional):  note of the record, the lengths of the note is unlimit.

      Add a record to the program.

  - update::
      Usage: update record_id value [note]

      args:
        - record_id:  the id of the record, `ls` is a useful command for lookup the record id.

      Update a record to the program.

  - delete::
      Usage: delete record_id

      args:
        - record_id:  the id of the record, `ls` is a useful command for lookup the record id.

      Delete a record to the program.

Example
-------

some instance::

  ➜  papyrus ✗ python papyrus.py
  Papyrus: A simple cmd program that manage the infomation of passwords.

  Enter Info's File Path (default `records.dat`): 
  Please Enter The Initiali Cipher: 
  (papyrus) >>> help

  Documented commands (type help <topic>):
  ========================================
  EOF  add  delete  info  ls  quit  update

  Undocumented commands:
  ======================
  help

  (papyrus) >>> add web yahoo apassword
  (papyrus) >>> ls groups
  * List all (group_id, group) pairs:
	(0, web)
	(1, 银行)
  (papyrus) >>> ls 0
  * List all infomation of the records in Group - `web`:
	(record_id, group, itemname, value)
	(0, web, google, a****2)
	(2, web, 团购, t****0)
	(3, web, yahoo, a****d)
  (papyrus) >>> ls 1
  * List all infomation of the records in Group - `银行`:
	(record_id, group, itemname, value)
	(1, 银行, 招行, q****3)
  (papyrus) >>> info 3
  The infomation of record - `3`:
         id:  3
        gid:  0
      group:  web
     record:  yahoo
      value:  apassword
       note:  None
    created:  2012-10-19_22:24:31.656777
     update:  2012-10-19_22:24:31.656777
  (papyrus) >>> 

