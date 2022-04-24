The `integration-test` directory tests insert and find with an FLE 2 indexed encrypted field.

This requires a local checkout of the Go driver to the [create-drop-encrypted-collection](https://github.com/kevinAlbs/mongo-go-driver/tree/create-drop-encrypted-collection) branch for the FLE 2  CreateCollection() and Drop() behavior. Modify the `replace` directive in go.mod to refer to a local checkout.

```
cd integration-test
./run.sh
```