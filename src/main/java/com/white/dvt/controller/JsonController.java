package com.white.dvt.controller;

import com.white.dvt.controller.param.JsonFormatParam;
import com.white.dvt.utils.JsonUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController("jsonController.v1")
@RequestMapping("/v1/json")
public class JsonController {

    @PostMapping(value = "/format")
    public String format(@RequestBody JsonFormatParam param) {
        return JsonUtils.formatByGson(param.getJson());
    }

}
