import { base64urlToBuffer } from "./base64.js";
function publicKeyCredentialToFormData(credential, name) {
    const formData = new FormData();
    formData.set(`${name}[id]`, credential.id);
    formData.set(`${name}[rawId]`, new File([credential.rawId], 'rawId', { type: 'application/octet-stream' }));
    formData.set(`${name}[type]`, credential.type);
    formData.set(`${name}[response][clientDataJSON]`, new File([credential.response.clientDataJSON], 'clientDataJSON', { type: 'application/json' }));
    if (credential.response instanceof AuthenticatorAttestationResponse) {
        formData.set(`${name}[response][attestationObject]`, new File([credential.response.attestationObject], 'attestationObject', { type: 'application/octet-stream' }));
    }
    if (credential.response instanceof AuthenticatorAssertionResponse) {
        formData.set(`${name}[response][authenticatorData]`, new File([credential.response.authenticatorData], 'authenticatorData', { type: 'application/octet-stream' }));
        formData.set(`${name}[response][signature]`, new File([credential.response.signature], 'signature', { type: 'application/octet-stream' }));
        if (credential.response.userHandle) {
            formData.set(`${name}[response][userHandle]`, new File([credential.response.userHandle], 'userHandle', { type: 'application/octet-stream' }));
        }
    }
    return formData;
}
export class PublicKeyCredentialElement extends HTMLElement {
    static formAssociated = true;
    #internals;
    #formData;
    #autofillAbortController = null;
    constructor() {
        super();
        this.#internals = this.attachInternals();
        this.#formData = new FormData();
    }
    get form() {
        return this.#internals.form;
    }
    get name() {
        return this.getAttribute('name');
    }
    set name(value) {
        this.setAttribute('name', value);
    }
    get type() {
        return this.localName;
    }
    get validity() {
        return this.#internals.validity;
    }
    get conditional() {
        return this.hasAttribute('conditional');
    }
    set conditional(value) {
        if (value) {
            this.setAttribute('conditional', '');
        }
        else {
            this.removeAttribute('conditional');
        }
    }
    get validationMessage() { return this.#internals.validationMessage; }
    get willValidate() { return this.#internals.willValidate; }
    checkValidity() { return this.#internals.checkValidity(); }
    reportValidity() { return this.#internals.reportValidity(); }
    get challenge() {
        const challenge = this.getAttribute('challenge');
        if (!challenge) {
            return null;
        }
        return base64urlToBuffer(challenge);
    }
    get allowCredentials() {
        const allowCredentials = this.getAttribute('allow-credentials');
        if (!allowCredentials) {
            return [];
        }
        if (allowCredentials === '') {
            return [];
        }
        return allowCredentials.split(" ").map((credential) => {
            return {
                type: 'public-key',
                id: base64urlToBuffer(credential)
            };
        });
    }
    async connectedCallback() {
        if (this.conditional) {
            const credential = await this.getCredentials(this.conditional);
            if (credential && this.name) {
                const formData = publicKeyCredentialToFormData(credential, this.name);
                this.#internals.setFormValue(formData, "hello");
                this.#internals.form?.requestSubmit();
            }
        }
        else {
            this.#internals.form?.addEventListener('submit', async (event) => {
                event.preventDefault();
                const credential = await this.getCredentials(this.conditional);
                if (credential && this.name) {
                    const formData = publicKeyCredentialToFormData(credential, this.name);
                    this.#internals.setFormValue(formData, this.getAttribute('challenge'));
                }
                this.#internals.form?.submit();
            });
        }
    }
    async disconnectedCallback() {
    }
    async getCredentials(conditional) {
        if (conditional && (!PublicKeyCredential.isConditionalMediationAvailable || !await PublicKeyCredential.isConditionalMediationAvailable())) {
            return null;
        }
        if (!this.challenge) {
            return null;
        }
        this.#autofillAbortController?.abort();
        this.#autofillAbortController = new AbortController();
        const credential = await navigator.credentials.get({
            mediation: conditional ? 'conditional' : 'required',
            signal: this.#autofillAbortController.signal,
            publicKey: {
                challenge: this.challenge,
                allowCredentials: this.allowCredentials
            }
        });
        return credential;
    }
}
customElements.define('public-key-credential', PublicKeyCredentialElement);
