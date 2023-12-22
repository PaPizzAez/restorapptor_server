const express = require("express")
const mysql = require("mysql2/promise")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")

const app = express()
const SECRET_PHRASE = "my_secret_phrase"

app.use(express.json())

const verifyToken = (req, res, next) => {
	const authHeader = req.headers["authorization"]
	const token = authHeader && authHeader.split(" ")[1]

	if (!token) {
		return res.json({code: 401, message: "Unauthorized: Token not provided"})
	}

	jwt.verify(token, SECRET_PHRASE, (err, decoded) => {
		if (err) {
			return res.json({code: 403, message: "Forbidden: Invalid token"})
		}

		req.user = decoded
		next()
	})
}

app.post("/register", async (req, res) => {
	const {name, password} = req.body

	try {
		if (typeof name !== "string" || name.length === 0)
			throw new Error("Empty name parameter!")

		if (typeof password !== "string" || password.length <= 3)
			throw new Error("Empty password parameter!")

		const connection = await mysql.createConnection({
			host: "localhost",
			user: "root",
			password: "",
			database: "restorapptor",
		})

		const encryptedPassword = await bcrypt.hash(password, 10)

		const data = await connection.execute(`
			INSERT INTO users (name, password)
			VALUES (?, ?)
		`, [name, encryptedPassword])

		if (!data || data.length === 0 || typeof data[0]?.insertId !== "number")
			throw new Error(`Can't insert row with name=${name}!`)

		const token = jwt.sign(
			{
				id: data[0]?.insertId,
				name
			},
			SECRET_PHRASE,
			{expiresIn: "32h"}
		)

		res.json({ code: 200, token })
	} catch (e) {
		res.json({
			code: 500,
			message: e?.message ?? "Internal server error"
		})
	}
})

app.post("/login", async (req, res) => {
	const {name, password} = req.body

	try {
		if (typeof name !== "string" || name.length === 0)
			throw new Error("Empty name parameter!")

		if (typeof password !== "string" || password.length <= 3)
			throw new Error("Empty password parameter!")

		const connection = await mysql.createConnection({
			host: "localhost",
			user: "root",
			password: "",
			database: "restorapptor",
		})

		const [userData] = await connection.execute(`SELECT id, name, password FROM users WHERE name = ?`, [name])

		if (!userData || userData.length === 0)
			throw new Error("User not found")

		const { id, name: userName, password: hashedPassword } = userData[0]
		const passwordMatch = await bcrypt.compare(password, hashedPassword)

		if (!passwordMatch) throw new Error("Invalid password")

		const token = jwt.sign(
			{
				id,
				name: userName
			},
			SECRET_PHRASE,
			{expiresIn: "32min"}
		)

		res.json({ code: 200, token })
	} catch (e) {
		res.json({
			code: 500,
			message: e?.message ?? "Internal server error"
		})
	}
})

app.get("/tables", verifyToken, async (req, res) => {
	try {
		const name = req.user.name

		const connection = await mysql.createConnection({
			host: "localhost",
			user: "root",
			password: "",
			database: "restorapptor",
		})

		const [data] = await connection.execute(`
			SELECT
			    t.*,
			    CASE
			        WHEN o.id IS NULL THEN 'available'
			        WHEN o.userName = '${name}' THEN 'mine'
			        ELSE 'reserved'
			    END AS tableStatus
			FROM
			    tables t
			LEFT JOIN
			    orders o ON t.id = o.tableId;
		`)

		res.json({ code: 200, data })
	}
	catch (e) {
		res.json({
			code: 500,
			message: e?.message ?? "Internal server error"
		})
	}
})

app.get("/food_menu", verifyToken, async (req, res) => {
	try {
		const name = req.user.name

		const connection = await mysql.createConnection({
			host: "localhost",
			user: "root",
			password: "",
			database: "restorapptor",
		})

		const [data] = await connection.execute(`
			SELECT * FROM food_menu
		`)

		res.json({ code: 200, data })
	}
	catch (e) {
		res.json({
			code: 500,
			message: e?.message ?? "Internal server error"
		})
	}
})

app.post("/order_table", verifyToken, async (req, res) => {
	try {
		const name = req.user.name
		const {selectedTableId, foodBuyList} = req.body

		const connection = await mysql.createConnection({
			host: "localhost",
			user: "root",
			password: "",
			database: "restorapptor",
		})

		const data = await connection.execute(`
			INSERT INTO orders (tableId, userName, foodList)
			VALUES (?, ?, ?);
		`, [selectedTableId, name, JSON.stringify(foodBuyList)])

		res.json({ code: 200 })
	}
	catch (e) {
		res.json({
			code: 500,
			message: e?.message ?? "Internal server error"
		})
	}
})

app.get("/my_orders", verifyToken, async (req, res) => {
	try {
		const name = req.user.name

		const connection = await mysql.createConnection({
			host: "localhost",
			user: "root",
			password: "",
			database: "restorapptor",
		})

		const [data] = await connection.execute(`
			SELECT * FROM \`orders\` WHERE userName = ?
		`, [name])

		res.json({ code: 200, data })
	}
	catch (e) {
		res.json({
			code: 500,
			message: e?.message ?? "Internal server error"
		})
	}
})

app.delete("/remove_order", verifyToken, async (req, res) => {
	try {
		const name = req.user.name
		const {tableId} = req.body

		const connection = await mysql.createConnection({
			host: "localhost",
			user: "root",
			password: "",
			database: "restorapptor",
		})

		await connection.execute(`
			DELETE FROM orders
			WHERE id = ? AND userName = ?;
		`, [tableId, name])

		res.json({ code: 200 })
	}
	catch (e) {
		res.json({
			code: 500,
			message: e?.message ?? "Internal server error"
		})
	}
})

const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
	console.log(`Server is running on port http://localhost:${PORT}`)
})
