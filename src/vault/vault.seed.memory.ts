import { HttpService } from "@nestjs/axios"
import { Injectable, Logger, OnModuleInit } from "@nestjs/common"
import { ConfigService } from "@nestjs/config"
import { AxiosResponse } from "axios"
import { sha512_256 } from "js-sha512"
import base32 from "hi-base32"
import { ready, crypto_sign_seed_keypair, KeyPair, crypto_sign_detached } from "libsodium-wrappers-sumo"


@Injectable()
export class VaultSeedMemory {
    private latestToken: string

	constructor(private readonly httpService: HttpService, private readonly configService: ConfigService) {}

	async onModuleInit() {
		await this.auth(this.configService.get<string>("VAULT_TOKEN"))
	}

	async auth(token: string): Promise<boolean> {
		let isOkay: boolean = false
		try {
			const res: AxiosResponse = await this.httpService.axiosRef.get("http://localhost:8200/v1/sys/auth", {
				headers: {
					"X-Vault-Token": token,
				},
			})
	
			isOkay = res.status === 200
			if (isOkay) this.latestToken = token
		} catch (error) {
			isOkay = false
			Logger.error("Failed to auth to vault", "VaultService.auth")
			}
			
			return isOkay
			}
			
			// method to fetch seed from cubbyhole secret engine
			async fetchSeed(): Promise<Uint8Array> {
				const res: AxiosResponse = await this.httpService.axiosRef.get("http://localhost:8200/v1/secret/data/seed", {
					headers: {
						"X-Vault-Token": this.latestToken,
			},
		})
		
		const seed: Uint8Array = new Uint8Array(Buffer.from(res.data.data.data.seed, 'hex'))
		return seed
	}

	// write seed, return okay or error
	async writeSeed(seed: string): Promise<boolean> {

		const res: AxiosResponse = await this.httpService.axiosRef.post(
			"http://localhost:8200/v1/secret/data/seed",
			{
				data: { 
					seed: seed
				}
			},
			{
				headers: {
					"X-Vault-Token": this.latestToken,
				},
			}
		)

		return res.status === 204
	}

	/**
	 * 
	 */
	async keyGenFromSeed(): Promise<Uint8Array> {
		const seed: Uint8Array = await this.fetchSeed()

		// log size

		// libsodium key pair from seed
		await ready
		const keyPair: KeyPair = crypto_sign_seed_keypair(seed)

		// encode into algorand address
		const keyHash: string = sha512_256.create().update(keyPair.publicKey).hex()

		// last 4 bytes of the hash
		const checksum: string = keyHash.slice(-8)

		const addr: string = base32.encode(VaultSeedMemory.ConcatArrays(keyPair.publicKey, Buffer.from(checksum, "hex"))).slice(0, 58)
		
		return keyPair.publicKey
	}

	async signWithSeed(data: Buffer): Promise<Uint8Array> {
		const seed: Uint8Array = await this.fetchSeed()
		await ready
		const keyPair: KeyPair = crypto_sign_seed_keypair(seed)
		const signature: Uint8Array = crypto_sign_detached(data, keyPair.privateKey)
		return signature
	}

	static ConcatArrays(...arrs: ArrayLike<number>[]) {
		const size = arrs.reduce((sum, arr) => sum + arr.length, 0)
		const c = new Uint8Array(size)

		let offset = 0
		for (let i = 0; i < arrs.length; i++) {
			c.set(arrs[i], offset)
			offset += arrs[i].length
		}

		return c
	}
}