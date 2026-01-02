var var_2 = function() {
    var var_0 = arguments[0];
    var var_1 = arguments[1];
    return (var_0 + var_1);
};
var var_4 = function() {
    var var_3 = arguments[0];
    console.log((("Hello, " + var_3) + "!"));
    return (("Hello, " + var_3) + "!");
};
var var_5 = var_2(5, 3);
console.log(("5 + 3 = " + var_5));
var_4("World");
var var_6 = [1, 2, 3, 4, 5];
console.log("Array:", var_6);
var var_7 = { version: "1.0.0", name: "Test App" };
console.log("Config:", var_7);