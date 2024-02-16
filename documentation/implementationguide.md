# Implementation Guide  
> Please refer to the prerequisites page prior to making any calls. The prerequisites page can be referred on the [link]() here. 
## How to Utilize API
This section will guide the developer on how to implement one of ConnectPay's APIs. We will use the "Add Consumer Profile" API for this example as well as the "Create Session Token" API as it is a mandatory substep to use most of ConnectPay's API.

###  Step 1: Create Session Token
<p>
The Create Session Token API call is used to create a session token and to retrieve the RSA public key. This API is secured as it requires the Authorization header that can only be derived using the API Secret stored in the Merchant’s server. Below is more information on the API specification as well as example request and response payloads. <p>

[![](/assets/images/button.png '')](https://qa-developer.fiserv.com/product/ConnectPay/api/?type=post&path=/security/createsessiontoken&branch=develop&version=1.0.0)


Example Request Payload:

Use the payload below to create the Authorization Header.
```json
{
  "security": {
    "publicKeyRequired": true
  }
}
```

Example Response Payload:
```json
{
    "transactionStatus": "APPROVED",
    "transactionStatusCode": 0,
    "referenceTransactionID": "bedceb8b-2445-b1d5-4c1e-c09446099023",
    "transactionStatusDescription": "OK",
    "security": {
        "tokenID": "0HMxmsoYJRfAiGdxEsjcso3K8uY6",
        "issuedOn": "1583174178590",
        "expiresInSeconds": "599",
        "publicKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArAhyMQmqTL798rKAixN9jtnp4SFF5PVpqc/HKNprSSoaANsnpJLSTRLFMCuQIa2dcgFZM+nSPvSCGowD65/tMWBHTWfeXiSV1xWmhPdEQRocmUaRp3HoEO3RU1n5os9jQLMGEcyxopgtTvUydJSrjLWNGcC9UC50HIEBEOBqycRvqlI/oRO1oBIx8UPAe/dGKTO8Bx8f6J4Lyi5ilW0gFFYSni/Krg/fMrxu6luyGmBOr2H9zy6fv+8dLQd0LEoOAaZ/2RLfcTPnheyV7eUOvOS4DGISiQBRpXyu9Zlo1B3GbiXX8NkfCo2ByDq+6gELji7Tr+gT+zuj+5H12eQIDAQAB",
        "algorithm": "RSA/None/PKCS1Padding",
        "status": "ACTIVE"
    }
}
```
### Step 2: Add Consumer Profile
> Note: This section will teach how to utilize the guide once the prerequisites have been completed.

At this step, all prerequisites have been complete in order to make our first call. First, the request payload must be created. The entire payload must be encrypted using different encryption methods. It must also be decrypted in order to decode the response payload into something that is readable. We will use the "Add Consumer Profile" as the example API. 

> Note: We will need to use the "tokenID" for the "Client-Token" header as well as the RSA "publicKey" in order to encrypt a portion of the payload before making the API call. Save these two pieces of information from the "Create Session Token" API used earlier in order to complete the call.


#### Add Consumer Profile
The Create Consumer Profile call is mandatory for any new user enrollment. This is used to create an fdCustomerID for a provided external id (and other user information) by the merchant. <p>

[![](/assets/images/button.png '')](https://qa-developer.fiserv.com/product/ConnectPay/api/?type=post&path=/consumerprofile/add&branch=develop&version=1.0.0)

#### Create Request Payload
First and foremost, we need to create the request payload prior to encryption. The "externalID" can be whatever the developer would like. It is a unique identifier for each consumer and the should be incremented with each unique consumer. An example payload is shown below:
```json
{
    "customer": {
        "externalID": "Merchant01Customer00000000"
    }
}
```

>Note: We need to next create the HMAC Authorization header using the payload above. The Authorization header and HMAC methodology is discussed earlier in the prerequisite section.

#### Encrypt the AES key and IV
From above prerequisites section, we implemented the methodology to create the AES key and IV. We will use the publicKey generated from the "Create Session Token" API in order to encrypt the generated AES Key as "componentX" and the IV as "componentY". An example of the encrypted input is shown below:
```json
    "componentX": "ju5PPi7k4K2jtI0z47qKcHnQGRrIymN+dK+PVlWjKyufoaUHJqjqOAbjsQZ0q3sLciBkEVWm5jGbWQoGf2e9Us+yfYu8ua2hz3wOIRSymHdx8qKuoexQiKhLWnp/GAL0+TIdzb/CvNijuJkOe1XSzEoFdFjYgRNMV8LJM3G/izn48kZm9gexM/iJenJyzwFoqXJc7EcWrC3C0RlkBF5jTgZzTGCvBpxDq4pw3CjFDsGvFy5Gg26B1KRcRDctrFpLV697QAW//hWyS91NYB68S3TIo/B6/LfUjj9bOY3fM+i+5BY2oV7zbLLyvA+CKfLFRBoXtevfBJyndrUDFD0EBA==",
    "componentY": "CqTTfUbNR66rGRhAKGqnEYJBGona07l2lvV7s7sEG97b0eohkWCqcw/XhCSy2+A6rYxhhuvvQ+orjfmCzssIl4Uz+4gu3GE3lfMGeykjRuhipyV+fjnjOBcw/VDOg3IXffr4Oe/isRYTZ5gp0uht89Rpu9VXfWktKH5uEJiZdNyD9TY+xZ2Ekwc6trDjTSFPbxVNaITJGqMBFsuWXGcHvaqoo6bC7Q9r/pVsUHq5KDdoi0zuW+xBilMxk/hZE8fBifXkUZ+KGGibyHlseh/uH9U32UHgvyVSsiUjI1j44WNulRnvfN7Mi5HozJTiYbX2iGrL5QQLKkQIWQPWV37VgQ=="
```

#### Encrypt The Request Payload
Using the AES key and IV we will then encrypt the request payload using the AES encryption method. An example of the encrypted input is shown below:
```json
"componentDelta": "OEIyAAUL1Py3/oKewtNXswtkYOw+krJP0EFhucFWFXSug0TCV7kqL67Mk5PTzVqNWTAyPl0lK6ac2EBK3kxskC6WpzpJI4qSv7/9JSfQ7zAYUiKAKPobIXpHAJ7BuHSMlMkv/6UTJvdIRsgDaqfAbD5pqG5KDbRzXpzmLIpVJnGyPCkwwm+F36wGbe1ccuvzDHNL77e6XSmm2LpzO/NAGJRjMGXdLQ9XKFvjr/gK0ruO2gdqglomlvy3MG8BSvLCAYkOL1CAB4wF8ovsfpOAAV92KRdqxeMISntCc0/Fxg7fs9JILmn4ZkgiSgha1CsN"
```

#### Finalize the Request Payload
Using the newly encrypted data, we can then create the JSON that will be used in the request call. An example of the input is shown below:
```json
{
    "componentX": "ju5PPi7k4K2jtI0z47qKcHnQGRrIymN+dK+PVlWjKyufoaUHJqjqOAbjsQZ0q3sLciBkEVWm5jGbWQoGf2e9Us+yfYu8ua2hz3wOIRSymHdx8qKuoexQiKhLWnp/GAL0+TIdzb/CvNijuJkOe1XSzEoFdFjYgRNMV8LJM3G/izn48kZm9gexM/iJenJyzwFoqXJc7EcWrC3C0RlkBF5jTgZzTGCvBpxDq4pw3CjFDsGvFy5Gg26B1KRcRDctrFpLV697QAW//hWyS91NYB68S3TIo/B6/LfUjj9bOY3fM+i+5BY2oV7zbLLyvA+CKfLFRBoXtevfBJyndrUDFD0EBA==",
    "componentY": "CqTTfUbNR66rGRhAKGqnEYJBGona07l2lvV7s7sEG97b0eohkWCqcw/XhCSy2+A6rYxhhuvvQ+orjfmCzssIl4Uz+4gu3GE3lfMGeykjRuhipyV+fjnjOBcw/VDOg3IXffr4Oe/isRYTZ5gp0uht89Rpu9VXfWktKH5uEJiZdNyD9TY+xZ2Ekwc6trDjTSFPbxVNaITJGqMBFsuWXGcHvaqoo6bC7Q9r/pVsUHq5KDdoi0zuW+xBilMxk/hZE8fBifXkUZ+KGGibyHlseh/uH9U32UHgvyVSsiUjI1j44WNulRnvfN7Mi5HozJTiYbX2iGrL5QQLKkQIWQPWV37VgQ==",
    "componentDelta": "OEIyAAUL1Py3/oKewtNXswtkYOw+krJP0EFhucFWFXSug0TCV7kqL67Mk5PTzVqNWTAyPl0lK6ac2EBK3kxskC6WpzpJI4qSv7/9JSfQ7zAYUiKAKPobIXpHAJ7BuHSMlMkv/6UTJvdIRsgDaqfAbD5pqG5KDbRzXpzmLIpVJnGyPCkwwm+F36wGbe1ccuvzDHNL77e6XSmm2LpzO/NAGJRjMGXdLQ9XKFvjr/gK0ruO2gdqglomlvy3MG8BSvLCAYkOL1CAB4wF8ovsfpOAAV92KRdqxeMISntCc0/Fxg7fs9JILmn4ZkgiSgha1CsN"
}
```

#### Make The Request
Using the correct endpoint, headers, and encrypted payload, we can then make the call. The ConnectPay backend will decrypt the payload and process the request. It will then return the response encrypted with the AES key and IV provided by componentX and componentY. An example of the output is shown below:
```json
{
"componentDelta": "cRD5xVaJab13iRQ7l6No6ot9YPTFT3bi/qapHYGgsNmxQ8nT2mtIz7uLLHz5kdp5JEmDjiP1dXMNPg8jP5rIZQf/5dtMfFLq7YL7FQY/boTsd7BoJg7reDeeAk6l9+76gaSAZMIRJGYS4fhy1bgClx2jIeWo4fLlfildeHnghCU1ElR8XhFi3oyd8hU+YEpDENP5IJJMVxjnYChuFX8paVy/SAYFMESBXSTIgPi6Y/kJc/bswlxaa9Yei4GnD+Ny1laVs4HqJp32JJ+NHJIYdZr5117AY0JJxJ9oudnkK6J8oPnnXhLCBGxNCRDJG3AVLRxDnQcds/cSiwAVREHr4nn848IEsUb27wJR7SiDxVaELxme9CNZ1dB0tPYQ1wux3ymWtnUgLfVRFsHH3EeucbHv8uIc8dxcwxZReROzVS8="
}
```

#### Decrypt the Response Payload
Decrypt ComponentDelta with the AES Key and IV generated earlier in order to decode the response payload into a readable form. An example of the decrypted output is shown below:
```json
{
    "transactionStatus": "APPROVED",
    "transactionStatusCode": 0,
    "referenceTransactionID": "5cdd1d99-5367-ed98-56fd-3f52ab008ac8",
    "transactionStatusDescription": "Created",
    "customer": {
        "fdCustomerID": "CP1GWQ15714280477520000262L7Wymj",
        "externalID": "Merchant01Consumer65746635"
    }
}
```

#### Verify Success of the Response Payload
Verify that the transaction was successful. As shown above, the transaction was approved and we can then move to using another ConnectPay API in order to complete consumer enrollment.

Congratulations, you have successfully used ConnectPay's API. The steps above apply to all ConnectPay API's except for the "Create Session Token" API and the "Get Public Key Service" API. These APIs do not need the request payload to be encrypted prior to making a call. Please repeat steps 1 and 2 for the API below to complete an ACH transaction.

### Step 3: Consumer Enrollment
There are two ways to enroll customers. The steps for either enrolling consumers through online bank login or manual enrollment are listed below. It is also possible to have both types of enrollment methods as part of the merchant application. 

<!--
type: tab
titles: Online Bank Login, Manual Enrollment
-->

### Step 3 Option 1: Online Bank Login


<span style="font-size: 1.25em; color: var(--bs-heading-color)">
Option 1: Online Bank Login
</span>

The online bank login is used when the end-user/consumer would like to login using their banking credentials in order to link their bank account to a payment method.
<details>
<summary>Step a: Establish Online Bank Login</summary>
<br>
Use this as the first step in online bank login process. The output from this service needs to be passed to online bank login processor to initiate the bank login IFRAME.<p>

[![](/assets/images/button.png '')](https://qa-developer.fiserv.com/product/ConnectPay/api/?type=post&path=/onlinebanklogin/establish&branch=develop&version=1.0.0)
</details>

<details>
<summary>Step b: Validate Online Bank Login</summary>
<br>
Use this method to after consumer has completed bank selection process, to pull all consumer information available on bank records to be displayed on consumer’s screen Consumer can view and edit the enrollment form prepopulated with the data from above step. Bank information is the only set of fields which should be not editable. <p>

[![](/assets/images/button.png '')](https://qa-developer.fiserv.com/product/ConnectPay/api/?type=post&path=/onlinebanklogin/validate&branch=develop&version=1.0.0)
</details>
<details>
<summary>Step c: Consumer Enrollment</summary>
<br>
The Consumer Enrollment call is for any new consumer enrollment purpose. This is used to perform a ConnectPay enrollment process for a provided consumer details payload. This API is secured, as it requires the Authorization header that can only be derived using the API Secret stored in the Merchant’s web server. <p>

[![](/assets/images/button.png '')](https://qa-developer.fiserv.com/product/ConnectPay/api/?type=post&path=/consumerprofile/enrollment&branch=develop&version=1.0.0)
</details>

<!--
type: tab
-->

<span style="font-size: 1.25em; color: var(--bs-heading-color)">
Option 2: Manual Enrollment
</span>

The manual enrollment is used when the end-user/consumer does not want to login with their bank credentials and would rather deposit smaller amounts using information such as the bank routing and account number.
<details>
<summary>Step a: Consumer Enrollment</summary>
<br>
The Consumer Enrollment call is for any new consumer enrollment purpose. This is used to perform a ConnectPay enrollment process for a provided consumer details payload. This API is secured, as it requires the Authorization header that can only be derived using the API Secret stored in the Merchant’s web server. <p>

[![](/assets/images/button.png '')](https://qa-developer.fiserv.com/product/ConnectPay/api/?type=post&path=/consumerprofile/enrollment&branch=develop&version=1.0.0)
</details>

<details>
<summary>Step b: Micro-Deposit Validation</summary>
<br>
Use this method to complete micro deposit validation to authenticate your bank account after a manual enrollment.ConnectPayAPI Direct Integration Guide. Kindly note it might take a few days for the micro deposits to appear on your bank account. Once bank account is successfully authenticated, the ACH payment option gets activated for transaction. For MAS to ConnectPayAPI Server call, MAS needs to pass the fdAccountID in payload request. <p>

[![](/assets/images/button.png '')]()
</details>

<!-- type: tab-end -->


### Step 4: ACH Transactions
These APIs are for the merchant to implement depending on the use case of the end-user/consumer. These API's are exclusively used for some form of processing ACH transactions.
<details>
<summary>Purchase</summary>
<br>
Merchants who want to process ACH Transactions through FirstAPI must make server-to-server calls and pass necessary encrypted payload as required for that particular case. Use this to initiate purchase/sale transaction request where final amount is known. <p>

[![](/assets/images/button.png '')](https://qa-developer.fiserv.com/product/ConnectPay/api/?type=post&path=/transaction/purchase&branch=develop&version=1.0.0)
</details>

<details>
<summary>Authorize</summary>
<br>
Merchants who want to process ACH Transactions through FirstAPI must make server-to-server calls and pass necessary encrypted payload as required for that particular case. Use this to initiate purchase/sale transaction request where final amount is known. <p>

[![](/assets/images/button.png '')](https://qa-developer.fiserv.com/product/ConnectPay/api/?type=post&path=/transaction/authorize&branch=develop&version=1.0.0)
</details>


>You have successfully completed an ACH transaction. For information on other ConnectPay APIs, please look below for the API specification:


### Other APIs:
For more information on the other APIs within ConnectPay please visit the API Explorer on the navigation bar to the left.
