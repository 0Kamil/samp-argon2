# SampArgon2
A argon2 plugin for samp in Rust.

## Installation
* Download suitable binary files from releases for your operating system
* Add it your `plugins` folder
* Add `samp_argon2.dll` (for windows) or `samp_argon2.so` (for linux) to server.cfg
* Add [samp_argon2.inc](include/samp_argon2.inc) in includes folder

## API
* ##### argon2_hash(playerid, const callback[], const pass[], const salt[], variant, mem_cost, time_cost, lanes, hash_length, const args[] = "", {Float, _}:...)
	* `playerid` - id of the player
	* `callback[]` - callback to execute after hashing
	* `pass[]` - string to hash
	* `salt[]` - string to salt
	* `variant` - set variant
	* `mem_cost` - set mem cost
	* `time_cost` - set time cost
	* `lanes` - set lanes
	* `hash_length` - set hash length
	* `args[]` - custom arguments

	**Example**
	```Pawn
	main()
	{
		argon2_hash(0, "OnPasswordHash", "password", "somesalt", VARIANT_ARGON2I, 4096, 3, 1, 32);
	}

	forward OnPasswordHash(playerid);
	public OnPasswordHash(playerid)
	{
		//hashing completed
	}
	```
* ##### argon2_get_hash(const hash[], size = sizeof(hash))
	* `hash[]` - string to store hashed data
	* `size` - max size of hash string

	**Example**
	```Pawn
	main()
	{
		argon2_hash(0, "OnPasswordHash", "password", "somesalt", VARIANT_ARGON2I, 4096, 3, 1, 32);
	}

	forward OnPasswordHash(playerid);
	public OnPasswordHash(playerid)
	{
		new hash[85];
		argon2_get_hash(hash);
		printf("Hash: %s", hash);
	}
	```
* ##### argon2_verify(playerid, const callback[], const pass[], const hash[], const args[] = "", {Float, _}:...)
	* `playerid` - id of the player
	* `callback[]` - callback to execute after hashing
	* `pass[]` - text to compare with hash
	* `hash[]` - hash to compare with text
	* `args[]` - custom arguments
	
	**Example**
	```Pawn
	main()
	{
		argon2_hash(0, "OnPasswordHash", "password", "somesalt", VARIANT_ARGON2I, 4096, 3, 1, 32);
	}

	forward OnPasswordHash(playerid);
	public OnPasswordHash(playerid)
	{
		new hash[85];
		argon2_get_hash(hash);
		argon2_verify(playerid, "OnPasswordVerify", "password", hash);
	}

	forward OnPasswordVerify(playerid, bool:success);
	public OnPasswordVerify(playerid, bool:success)
	{
		//success denotes verifying was successful or not
		if(success)
		{
			//verfied
		}
		else
		{
			//hash doesn't match with text
		}
	}
	```
