#if defined _inc_samp_argon2
	#undef _inc_samp_argon2
#endif

#if defined _samp_argon2_included
	#endinput
#endif
#define _samp_argon2_included

#if !defined VARIANT_ARGON2D
	#define VARIANT_ARGON2D (0)
#endif

#if !defined VARIANT_ARGON2I
	#define VARIANT_ARGON2I (1)
#endif

#if !defined VARIANT_ARGON2ID
	#define VARIANT_ARGON2ID (2)
#endif

native argon2_hash(playerid, const callback[], const pass[], const salt[], variant, mem_cost, time_cost, lanes, hash_length, const args[] = "", {Float, _}:...);
native argon2_verify(playerid, const callback[], const pass[], const hash[], const args[] = "", {Float, _}:...);
native argon2_get_hash(const hash[], size = sizeof(hash));
