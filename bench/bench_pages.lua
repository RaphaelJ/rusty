n_pages = 500

request = function()
        r = math.random(0, n_pages)
        path = "/" .. r .. ".htm"
        return wrk.format(nil, path)
end

