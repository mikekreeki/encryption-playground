import { useState, useCallback } from 'react';
import { generateHash, generateKeys, decryptString } from './encryption';

function App() {
  const [password, setPassword] = useState('')
  const [salt, setSalt] = useState('')
  const [text, setText] = useState('')
  const [decrypted, setDecrypted] = useState('');

  const [isBusy, setBusy] = useState(false)
  const [isError, setError] = useState(false)

  const onPasswordChange = useCallback((e) => {
    setPassword(e.target.value);
    setDecrypted('');
    setError(false);
  }, [])

  const onSaltChange = useCallback((e) => {
    setSalt(e.target.value);
    setDecrypted('');
    setError(false);
  }, [])

  const onTextChange = useCallback((e) => {
    setText(e.target.value);
    setDecrypted('');
    setError(false);
  }, [])

  const onSubmit = useCallback(() => {
    setError(false)
    setBusy(true);

    setTimeout(async () => {
      try {
        const hash = await generateHash(password, salt);
        const { privateKey } = generateKeys(hash);

        setDecrypted(decryptString(privateKey, text))
      } catch (error) {
        setError(true)
        console.error(error)
      }

      setBusy(false);
    }, 100)
  }, [password, salt, text])

  return (
    <div style={{ padding: 24 }}>
      <div style={{ marginBottom: 16 }}>
        <input type="text" placeholder="password" onChange={onPasswordChange}  />
        <input type="text" placeholder="salt" onChange={onSaltChange}  />
        <input type="text" placeholder="encrypted text" onChange={onTextChange}  />
        <button disabled={isBusy} onClick={onSubmit}>Encrypt</button>
      </div>

      {isBusy && 'Processing...'}
      {isError ? 'Could not decrypt (see error in the console)' : decrypted }
    </div>
  );
}

export default App;
