@registry = Hash.new
@registry = Marshal.load(File.read("registry.dat"))
puts @registry
puts
@registry.each do |name, file|
    puts name
    puts "offset: #{file[:offset]}"
    puts "length: #{file[:length]}"
end
