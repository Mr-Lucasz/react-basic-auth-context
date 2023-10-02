const readline = require("readline");
const crypto = require("crypto");
const fs = require("fs");

async function obterCredenciais() {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  const username = await perguntaAsync(rl, "Digite o nome de usuário: ");
  const password = await perguntaAsync(rl, "Digite a senha: ");

  rl.close();

  return { username, password };
}

async function perguntaAsync(rl, pergunta) {
  return new Promise((resolve) => {
    rl.question(pergunta, (resposta) => {
      resolve(resposta);
    });
  });
}

function derivarChavePBKDF2(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 10000, 32, "sha256");
}

function criptografarSenha(senha, chave) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", chave, iv);

  const senhaCriptografada = Buffer.concat([
    cipher.update(senha, "utf8"),
    cipher.final(),
  ]);

  console.log("Senha criptografada:", senhaCriptografada.toString("hex"));

  return { senhaCriptografada, iv };
}

function salvarChaveEIV(chave, iv, arquivo) {
  const cipher = crypto.createCipheriv("aes-256-ecb", chave, Buffer.alloc(0));
  const encryptedData = Buffer.concat([cipher.update(iv), cipher.final()]);
  fs.writeFileSync(arquivo, encryptedData);
}

function lerChaveEIV(chave, arquivo) {
  try {
    const encryptedData = fs.readFileSync(arquivo);
    const decipher = crypto.createDecipheriv(
      "aes-256-ecb",
      chave,
      Buffer.alloc(0)
    );
    const iv = Buffer.concat([
      decipher.update(encryptedData),
      decipher.final(),
    ]);
    return iv;
  } catch (err) {
    console.error(
      "Erro ao ler o arquivo chaveEIV.txt. Certifique-se de criar o arquivo antes de executar o programa."
    );
    process.exit(1);
  }
}

async function main() {
  const credenciais = await obterCredenciais();
  const chavePBKDF2 = derivarChavePBKDF2(
    credenciais.password,
    Buffer.from("salt", "utf8")
  );

  const { senhaCriptografada, iv } = criptografarSenha(
    credenciais.password,
    chavePBKDF2
  );
  salvarChaveEIV(chavePBKDF2, iv, `${credenciais.username}_chaveEIV.txt`);
  fs.writeFileSync(
    "passwordFile.txt",
    `${credenciais.username}\n${senhaCriptografada.toString("hex")}`
  );
}

main();
