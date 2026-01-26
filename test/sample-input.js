function greet(name) {
  console.log("Hello, " + name + "!");
  return name.length;
}

var result = greet("World");
console.log("Length:", result);
